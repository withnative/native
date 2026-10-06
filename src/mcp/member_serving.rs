//! Member-copy serving foundation (contract c323277 rev 7 §2.2, §2.3, §2.6,
//! §6.1, §6.2; slice C2a).
//!
//! One runtime and one dispatch gate for reads served from an admitted
//! `member-read-v1` generation. C2a deliberately serves only the surfaces
//! that provably do not touch the slice and refuses every other surface
//! fail-closed with a typed error; C2b/C2c widen the allowlist. The gate runs
//! before any handler, so a refused surface never reaches storage.
//!
//! The gate is consulted from the registry dispatch beside
//! `admit_standby_call`, and the post-response hook scrubs every §2.6
//! counter-bearing field and injects the member-scope holding disclosure.
//!
//! ## `scan` over the slice (contract c323277 rev 8 §2.3(a))
//!
//! Richard's 30 Sep 2026 decision serves the computable scan axes over the
//! admitted slice and marks the two axes that need excluded history. The
//! corpus size, type/kind/lifecycle census, lexical, recent, high-degree and
//! container axes run at parity over the slice (member not-hidden constant,
//! slice presence for authorization, post-visibility counts/thresholds,
//! shipped `member_display_references` for samples).
//!
//! Two axes cannot be computed from the slice and become explicit
//! `unavailable_offline` markers (never empty buckets or zero counts):
//! `census.provenance` and `axes.authored_by`, surfaces `scan.provenance` and
//! `scan.authored_by`. Provenance reads each record's genesis
//! `content_events`, and authored_by reads its latest `content_events`; both
//! are excluded history. Convergence is computed over the served axes only and
//! the member response names those axes in `convergence_basis`
//! (`{kind: "served_axes", axes: [...], excluded_axes: ["authored_by"]}`), so a
//! reader can tell a served axis from a marked one.
//!
//! Excluded-table reads are replaced by the contract's member answer through
//! `ReadLens::member` branches rather than TEMP member-contract views. The
//! adopted design allows either; the lens is used because the member `Db`
//! opens immutable read-only pools (db.rs `open_member_database_read_only`),
//! and per-connection TEMP objects do not reliably persist across a pooled
//! connection set.
//!
//! ## Trust root (contract §0, §3.4)
//!
//! The reader trusts `slice = E(m)`. Per §3.4 the consumer proves only
//! internal closure; eligibility rests on the producer's full-evaluator fold
//! plus authenticated transport (`verification: producer_attested`). The
//! `overshipped_hidden_row_is_caught_by_the_differential` test proves the
//! differential harness detects a wrong slice; it does **not** claim the
//! device can reject one — admission accepts a digest-fixed oversized slice
//! by design, because re-deriving E(m) offline is impossible.
//!
//! ## The render-markdown marker contract
//!
//! `render_record` answers with prose, not a field tree, so it cannot carry the
//! per-section `unavailable_offline` markers `get_record` injects. The member
//! branch of `render_record` in `tools/lifecycle.rs` therefore renders only the
//! sections whose inputs the slice ships: title, the path over the shipped
//! `home_id` chain, the status line (lifecycle, persistence, maturity, visible
//! owner, visible successors, archived/deleted), summary, body, facets, links,
//! mentions, children and suggestions. Custody, contribution and history are
//! never rendered into markdown, so no prose section stands in for an excluded
//! read and no marker is required.
//!
//! The one excluded *opt-in* section is the interpretation projection: when
//! `include_interpretation` is set, the member response carries the single
//! marker shape at `interpretation`; when it is not set the key is absent,
//! exactly as online. A future member markdown section whose input is excluded
//! must be rendered as an explicit marker line (or the surface refused), never
//! omitted as if empty.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use sqlx::SqlitePool;

use crate::domain_transaction::request::ToolCallOutcome;
use crate::error::{Error, Result};
use crate::holding::HoldingDisclosureV2;
use crate::mcp::interactions::ToolKind;
use crate::mcp::member_scope::MemberScope;
use crate::member_copy_lifecycle::{CopyStatus, MemberCopyLifecycle, ReadDecision};

/// Surfaces C2a/C2c serve. Everything else in `MemberScope::Served`
/// (`Served`/`ServedPartial`/`SchemaGated`) is refused with
/// `unavailable_offline { requirement: "not_yet_served_offline" }` until a
/// later increment enables it.
///
/// `engine_info` uses compiled backend information and explicitly marks the
/// excluded workspace storage-policy overlay unavailable.
pub(crate) const MEMBER_SERVED_SURFACES: &[&str] = &[
    "ping",
    "engine_info",
    "standby_status",
    "read_guide",
    "quickstart",
    "get_record",
    "render_record",
    "search",
    "scan",
    "query_record",
    "bootstrap",
    "resolve_many",
    "get_structure",
    "get_dashboard",
    "read_attachment",
    "manage_attachments",
    "manage_links",
    "query_sql",
    "open_collection",
    "describe_schema",
    "preview_record_shape",
    "resolve_facets",
    "suggest_facet_values",
];

/// Surfaces whose interpretation depends on the admitted schema set, so a
/// withheld schema row (`schema_incomplete_for`, §3.3 rule 6) makes them refuse
/// rather than answer from an incomplete set. `open_collection` is included:
/// its enrichment interprets member records through `schema_config`. The four
/// named schema tools and `get_record`/`render_record` (`kind_governance`,
/// §2.4 item 12) and dashboard lifecycle interpretation use the same gate.
pub(crate) const MEMBER_SCHEMA_GATED_SURFACES: &[&str] = &[
    "get_dashboard",
    "get_record",
    "render_record",
    "describe_schema",
    "preview_record_shape",
    "resolve_facets",
    "suggest_facet_values",
    "open_collection",
];

/// The single dispatch gate for a member copy. It owns the lifecycle state
/// (read-only), the admitted holding coordinates and the generation's
/// `schema_incomplete_for` markers (§3.3 rule 6).
pub(crate) struct MemberCopyGate {
    lifecycle: Arc<Mutex<MemberCopyLifecycle>>,
    scope_ref: String,
    ordinal: i64,
    schema_incomplete_for: Vec<String>,
    /// Admitted `generation_id` (contract §1.3) bound into the member
    /// `query_record` page basis. Empty until the serving driver supplies the
    /// admitted generation; the basis then falls back to the lifecycle
    /// coordinates (`scope_ref`/`ordinal`), which are still trusted
    /// driver-supplied values, never caller input.
    generation_id: String,
    /// Serialized reader-league state shared with the serving owner (D1). A
    /// dispatch holds one lease for the whole handler plus response
    /// decoration, so a scope/account-change purge can drain every in-flight
    /// read before it deletes the old generation.
    leases: Arc<MemberCopyLeaseGate>,
    binding: MemberCopyBinding,
}

/// Immutable admission authority; a registry cannot substitute another handle.
enum MemberCopyBinding {
    Unbound,
    Admitted {
        handle_id: uuid::Uuid,
        account_token: String,
    },
    #[cfg(test)]
    TestUnchecked,
}

/// Serialized reader lease state for one member copy (D1).
///
/// `acquire` is the only way into a member dispatch. `deactivate` closes the
/// door (a call already queued but not yet admitted refuses), and `drain`
/// waits for every lease that won the race to drop. The pair is what makes
/// "quiesce readers before deleting the old generation" enforceable rather
/// than a documented hope: a lifecycle state mutex checked only at dispatch
/// cannot serialize an async handler through deletion.
pub(crate) struct MemberCopyLeaseGate {
    state: Mutex<LeaseState>,
    drained: tokio::sync::Notify,
}

#[derive(Default)]
struct LeaseState {
    active: bool,
    readers: usize,
}

/// One admitted read. Dropping it releases the reader slot and wakes a
/// draining owner when the last reader leaves.
pub(crate) struct MemberCopyLease {
    gate: Arc<MemberCopyLeaseGate>,
}

impl MemberCopyLeaseGate {
    pub(crate) fn new(active: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(LeaseState { active, readers: 0 }),
            drained: tokio::sync::Notify::new(),
        })
    }

    /// Takes a read lease, or refuses when the owner is quiescing/quiesced.
    /// The caller keeps it alive across the handler and every response
    /// projection.
    pub(crate) fn acquire(self: &Arc<Self>) -> Result<MemberCopyLease> {
        let mut state = self
            .state
            .lock()
            .expect("member lease lock is never poisoned");
        if !state.active {
            return Err(Error::copy_unavailable());
        }
        state.readers += 1;
        drop(state);
        Ok(MemberCopyLease { gate: self.clone() })
    }

    /// Closes the door. Returns whether this call transitioned active →
    /// inactive (idempotent otherwise).
    pub(crate) fn deactivate(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .expect("member lease lock is never poisoned");
        let was_active = state.active;
        state.active = false;
        was_active
    }

    /// Reopens the door after a validated admission.
    #[cfg(test)]
    pub(crate) fn reactivate(&self) {
        let mut state = self
            .state
            .lock()
            .expect("member lease lock is never poisoned");
        state.active = true;
    }

    /// Waits until no reader holds a lease. Safe to call before or after
    /// `deactivate`; callers deactivate first so no new lease can arrive.
    pub(crate) async fn drain(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .expect("member lease lock is never poisoned")
                .readers
                == 0
            {
                return;
            }
            notified.await;
        }
    }
}

impl Drop for MemberCopyLease {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .expect("member lease lock is never poisoned");
        state.readers = state.readers.saturating_sub(1);
        let drained = state.readers == 0;
        drop(state);
        if drained {
            self.gate.drained.notify_waiters();
        }
    }
}

impl MemberCopyGate {
    /// Composition seam for the member serving root (and tests). Not yet
    /// called outside tests in C2a; C2b installs it on the serving registry.
    #[cfg(test)]
    pub(crate) fn new(
        lifecycle: Arc<Mutex<MemberCopyLifecycle>>,
        scope_ref: String,
        ordinal: i64,
        schema_incomplete_for: Vec<String>,
    ) -> Self {
        Self {
            lifecycle,
            scope_ref,
            ordinal,
            schema_incomplete_for,
            generation_id: String::new(),
            leases: MemberCopyLeaseGate::new(true),
            binding: MemberCopyBinding::TestUnchecked,
        }
    }

    /// Production composition seam (D1): build the gate bound to the serving
    /// owner's shared lease state. Tests keep using [`Self::new`], which owns
    /// a private always-active lease gate, exactly as before.
    pub(crate) fn with_leases(
        lifecycle: Arc<Mutex<MemberCopyLifecycle>>,
        scope_ref: String,
        ordinal: i64,
        schema_incomplete_for: Vec<String>,
        leases: Arc<MemberCopyLeaseGate>,
    ) -> Self {
        Self {
            lifecycle,
            scope_ref,
            ordinal,
            schema_incomplete_for,
            generation_id: String::new(),
            leases,
            binding: MemberCopyBinding::Unbound,
        }
    }

    pub(crate) fn with_admission_binding(
        mut self,
        handle_id: uuid::Uuid,
        account_token: String,
    ) -> Self {
        self.binding = MemberCopyBinding::Admitted {
            handle_id,
            account_token,
        };
        self
    }

    /// Check before any dispatch, including a substituted canonical engine.
    pub(crate) fn validate_binding(
        &self,
        db: Option<&crate::db::Db>,
        caller: &super::registry::Caller,
    ) -> Result<()> {
        match &self.binding {
            MemberCopyBinding::Admitted {
                handle_id,
                account_token,
            } => {
                if db.is_some_and(|db| {
                    db.open_mode() == crate::db::DatabaseOpenMode::MemberReadOnly
                        && db.handle_id() == *handle_id
                }) && caller.credential() == account_token
                {
                    Ok(())
                } else {
                    Err(Error::copy_unavailable())
                }
            }
            MemberCopyBinding::Unbound => Err(Error::copy_unavailable()),
            #[cfg(test)]
            MemberCopyBinding::TestUnchecked => Ok(()),
        }
    }

    /// Narrow composition seam for the serving driver: record the admitted
    /// generation once admission (or refresh) promotes one. The member page
    /// basis binds this value, so a continuation minted under one generation
    /// refuses under any other — even when the visible id set is unchanged.
    pub(crate) fn with_generation_id(mut self, generation_id: String) -> Self {
        self.generation_id = generation_id;
        self
    }

    /// §3.3 rule 6 markers of the admitted generation: empty (complete),
    /// `["global"]`, or the visible collection ids whose gated row was
    /// withheld. Threaded to the dispatch caller so member handlers can apply
    /// the scoped half of the rule without probing hidden rows.
    pub(crate) fn schema_incomplete_for(&self) -> &[String] {
        &self.schema_incomplete_for
    }

    fn has_global_schema_marker(&self) -> bool {
        self.schema_incomplete_for
            .iter()
            .any(|marker| marker == "global")
    }

    /// True when a withheld schema row applies to `collection`: the marker list
    /// names exactly the visible collections whose row was withheld.
    fn schema_marker_applies_to(&self, collection: &str) -> bool {
        self.schema_incomplete_for
            .iter()
            .any(|marker| marker == collection)
    }

    /// Take one read lease for the whole dispatch (handler plus decoration).
    /// Refuses while the owner is quiescing, so a call queued behind a purge
    /// never reaches a handler over deleted bytes.
    pub(crate) fn begin_read(&self) -> Result<MemberCopyLease> {
        self.leases.acquire()
    }

    /// Trusted generation marker bound into the page basis: the admitted
    /// `generation_id` when the driver supplied one, else the lifecycle
    /// coordinates that already identify the admitted generation.
    fn generation_marker(&self) -> String {
        if self.generation_id.is_empty() {
            format!("scope:{}:ordinal:{}", self.scope_ref, self.ordinal)
        } else {
            self.generation_id.clone()
        }
    }

    /// Opaque member page basis: the pipeline's authorized ordered pre-page
    /// id digest bound to the admitted generation. Cross-generation
    /// continuations refuse even when the id sequence is unchanged.
    pub(crate) fn bind_page_basis(&self, raw_digest: &str) -> String {
        use sha2::{Digest as _, Sha256};
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                format!("{}|{raw_digest}", self.generation_marker()).as_bytes()
            ))
        )
    }

    /// Gate one call. Returns a typed refusal before any handler runs, so a
    /// refused call never touches storage.
    pub(crate) fn admit(
        &self,
        kind: Option<ToolKind>,
        name: &str,
        arguments: &Value,
    ) -> Result<()> {
        self.admit_copy_state()?;
        // §3.3 rule 6: a withheld *global* schema row makes the schema-derived
        // surfaces unanswerable everywhere, so they refuse rather than emit a
        // silently mis-interpreted interpretation. A collection-scoped
        // withholding refuses only where it applies: `open_collection` checks
        // its collection id here; the record-targeted schema tools and the
        // `open_collection` enrichment check the visible collection a member
        // record belongs to in their member branches (caller markers).
        if self.has_global_schema_marker() && MEMBER_SCHEMA_GATED_SURFACES.contains(&name) {
            return Err(Error::unavailable_offline(name, "schema_incomplete"));
        }
        if name == "open_collection" {
            if let Some(collection) = arguments.get("id").and_then(Value::as_str) {
                if self.schema_marker_applies_to(collection) {
                    return Err(Error::unavailable_offline(name, "schema_incomplete"));
                }
            }
        }
        // §3.3 rule 6 carry to `query_sql` (C4b review f4c1452): when the
        // generation withheld a schema row, the shipped `schema_config`
        // relation is not authoritative. A statement that reads it refuses
        // typed; the probe distinguishes a real read from a same-named
        // CTE/comment/literal. Classification failures are left to the
        // handler's own error.
        if name == "query_sql" && !self.schema_incomplete_for.is_empty() {
            if let Some(sql) = arguments.get("sql").and_then(Value::as_str) {
                if let Ok(statement) = crate::query::sql_contract::classify_single_read_statement(
                    crate::query::sql_contract::QuerySqlProfile::SqliteLocal,
                    sql,
                ) {
                    if crate::query::sql::member_reads_schema_config(&statement)? {
                        return Err(Error::unavailable_offline(name, "schema_config"));
                    }
                }
            }
        }
        let Some(kind) = kind else {
            return Err(Error::unavailable_offline(name, "unknown_surface"));
        };
        let scope = kind.member_scope();
        match scope {
            MemberScope::WriteRefused => Err(Error::standby_read_only()),
            MemberScope::UnavailableOffline => {
                Err(Error::unavailable_offline(name, "surface_unavailable"))
            }
            MemberScope::Served { refused_args, .. }
            | MemberScope::ServedPartial { refused_args, .. }
            | MemberScope::SchemaGated { refused_args, .. } => {
                for argument in refused_args {
                    if arguments
                        .get(argument.name())
                        .is_some_and(|value| !value.is_null())
                    {
                        return Err(Error::unavailable_offline(name, argument.name()));
                    }
                }
                if let Some(actions) = scope.refused_write_actions() {
                    if arguments
                        .get("action")
                        .and_then(Value::as_str)
                        .is_some_and(|action| actions.contains(&action))
                    {
                        return Err(Error::standby_read_only());
                    }
                }
                if MEMBER_SERVED_SURFACES.contains(&name) {
                    Ok(())
                } else {
                    Err(Error::unavailable_offline(name, "not_yet_served_offline"))
                }
            }
        }
    }

    /// Copy-level gate (§6.1, R6): reads refuse from status alone, before any
    /// surface logic. `removed` and a pending cleanup barrier are
    /// member-facingly indistinguishable (`copy_unavailable`); `locked` is
    /// its own typed state.
    fn admit_copy_state(&self) -> Result<()> {
        let (decision, status) = {
            let lifecycle = self
                .lifecycle
                .lock()
                .expect("member copy lifecycle lock is never poisoned");
            (lifecycle.read_decision(), lifecycle.status())
        };
        match decision {
            ReadDecision::Allow => Ok(()),
            ReadDecision::CopyLocked => Err(Error::copy_locked()),
            ReadDecision::UnavailableOffline => Err(match status {
                CopyStatus::Removed { cause, deletion } => Error::copy_removed(cause, deletion),
                _ => Error::copy_unavailable(),
            }),
        }
    }
}

impl MemberCopyGate {
    /// Post-response decoration: scrub the §2.6 counter-bearing *metadata*
    /// positions of this tool's shape and attach the member-scope holding
    /// disclosure. Applies to successful responses only; refusals are already
    /// counter-free typed errors. `tool` scopes the scrub: authored body, name,
    /// summary and facet payloads are never inspected by name or value.
    /// `arguments` carries the caller's continuation token for the
    /// `query_record` page-basis check below; it is read, never trusted for
    /// the binding itself.
    pub(crate) fn decorate(&self, tool: &str, arguments: &Value, outcome: &mut ToolCallOutcome) {
        let Ok(result) = &mut outcome.outcome else {
            return;
        };
        if tool == "query_record" {
            self.rebind_query_record_basis(arguments, &mut result.structured);
            // A stale continuation becomes the same typed refusal online
            // returns; it carries no counter and no record identity.
            if result
                .structured
                .get("page_basis_mismatch")
                .and_then(Value::as_bool)
                == Some(true)
            {
                result
                    .structured
                    .as_object_mut()
                    .expect("response is an object")
                    .remove("page_basis_mismatch");
                outcome.outcome = Err(Error::engine(
                    "query_record: record page basis changed under current authorization or schema; restart from offset 0",
                ));
                return;
            }
        }
        scrub_member_response(tool, &mut result.structured);
        if let Some(object) = result.structured.as_object_mut() {
            object.insert("standby_context".into(), self.context_value());
        }
    }

    /// Bind the member `query_record` page basis to the admitted generation
    /// and verify the caller's continuation token against it. The raw digest
    /// is the pipeline's authorized ordered pre-page id sequence; the bound
    /// basis additionally commits to the generation, so a token minted under
    /// one generation refuses under any other — even when the visible ids
    /// are unchanged. Counter positions are left for the scrub below; only
    /// the opaque digests are rewritten here.
    fn rebind_query_record_basis(&self, arguments: &Value, result: &mut Value) {
        let Some(object) = result.as_object_mut() else {
            return;
        };
        if let Some(raw) = object
            .get("page_basis_digest")
            .and_then(Value::as_str)
            .map(str::to_owned)
        {
            object.insert(
                "page_basis_digest".into(),
                serde_json::json!(self.bind_page_basis(&raw)),
            );
        }
        if let Some(next) = object
            .get_mut("next_request")
            .and_then(Value::as_object_mut)
        {
            if let Some(raw) = next
                .get("if_page_basis_digest")
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                next.insert(
                    "if_page_basis_digest".into(),
                    serde_json::json!(self.bind_page_basis(&raw)),
                );
            }
            next.remove("as_of");
        }
        if let Some(expected) = arguments
            .get("if_page_basis_digest")
            .and_then(Value::as_str)
        {
            let current = object
                .get("page_basis_digest")
                .and_then(Value::as_str)
                .unwrap_or("");
            if current != expected {
                object.insert("page_basis_mismatch".into(), serde_json::json!(true));
            }
        }
    }

    /// §2.6: the member `standby_context` is the scope holding with ordinal —
    /// never a frontier, act, or workspace counter (R5).
    fn context_value(&self) -> Value {
        serde_json::to_value(HoldingDisclosureV2::member(
            self.scope_ref.clone(),
            self.ordinal,
        ))
        .expect("member holding v2 is JSON")
    }
}

/// §2.6/R5 defence in depth: remove counter-bearing *metadata* from a member
/// response at its KNOWN positions for `tool`'s shape. It deliberately never
/// inspects arbitrary keys or string values, because authored body, name,
/// summary and facet text ships verbatim (§3.3 rule 4) and every other field
/// is at parity (§2.3): a user string that happens to read `rec:123` or
/// `obs:456`, or an authored JSON key named `seq`, is payload, not a counter.
/// Each omission is positional; new served surfaces register their metadata
/// positions here (see `query_sql`/`query_record` notes below).
pub(crate) fn scrub_member_response(tool: &str, value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    remove_envelope_counter_fields(object);
    if tool == "get_record" {
        if let Some(records) = object.get_mut("records").and_then(Value::as_array_mut) {
            for item in records {
                scrub_record_item_counters(item);
            }
        }
    }
    // `search` hits and `scan` samples carry no counter metadata (scores,
    // snippets, evidence, shipped references only).
    //
    // C2c-4 `query_sql`: only the envelope's `as_of_seq` is omitted (above).
    // Relation rows are returned at parity, including user-authored column
    // aliases such as `seq`; never scrub by row key or cell value.
    // C2c-4 `query_record`: the page snapshot's `as_of.content_seq` and
    // `content_head_seq` are omitted (above); the page rows are parity.
}

/// Envelope positions that are always server metadata: the owner manifest
/// coordinates (never sent to a member) and the §2.6 log-position fields.
fn remove_envelope_counter_fields(object: &mut serde_json::Map<String, Value>) {
    for key in [
        "act",
        "head_act",
        "frontier",
        "as_of_seq",
        "content_head_seq",
        "previous_seq",
        "local_seq",
        "event_seq",
        "source_event_seq",
        "authorization_revision",
        "authorization_revision_epoch",
    ] {
        object.remove(key);
    }
    if object.get("acts").is_some_and(|acts| !acts.is_null()) {
        object.remove("acts");
    }
    if let Some(as_of) = object.get_mut("as_of").and_then(Value::as_object_mut) {
        for key in [
            "content_seq",
            "content_head_seq",
            "content_event_seq",
            "meta_event_seq",
            "authorization_revision",
        ] {
            as_of.remove(key);
        }
    }
}

/// Record positions that carry the §2.6 `rec:`/`obs:` version tokens. Authored
/// record fields (`name`, `body`, `summary`, facet values) are untouched.
fn scrub_record_item_counters(item: &mut Value) {
    let Some(item) = item.as_object_mut() else {
        return;
    };
    item.remove("version");
    if let Some(facets) = item.get_mut("facets").and_then(Value::as_array_mut) {
        for facet in facets {
            if let Some(facet) = facet.as_object_mut() {
                facet.remove("version");
            }
        }
    }
}

/// Member-safe visibility: a record id is visible iff it exists in the slice
/// (every row in a member copy is E(m) by construction). This replaces the
/// engine policy/Unit fold for member serving; it never reads
/// `semantic_units`, `record_policies` or `policy_entries` (contract §1.3,
/// §3.2). Unused until C2b wires the readers; tested here.
#[allow(dead_code)]
pub(crate) async fn slice_visible_ids(
    pool: &SqlitePool,
    ids: Vec<String>,
) -> Result<HashSet<String>> {
    if ids.is_empty() {
        return Ok(HashSet::new());
    }
    let encoded = serde_json::to_string(&ids)?;
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT r.id FROM records r WHERE r.id IN (SELECT value FROM json_each(?))",
    )
    .bind(encoded)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().collect())
}

/// Transaction-scoped form of [`slice_visible_ids`], for the shared
/// per-id visibility fold the MCP reader layer calls.
pub(crate) async fn slice_visible_ids_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    ids: &[String],
) -> Result<HashSet<String>> {
    if ids.is_empty() {
        return Ok(HashSet::new());
    }
    let encoded = serde_json::to_string(ids)?;
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT r.id FROM records r WHERE r.id IN (SELECT value FROM json_each(?))",
    )
    .bind(encoded)
    .fetch_all(&mut **tx)
    .await?;
    Ok(rows.into_iter().collect())
}

/// §3.3 rule 6 scoped applicability, for a member handler that knows the
/// collection a schema interpretation depends on. `true` when the admitted
/// generation withheld a schema row that applies: a `global` marker applies
/// everywhere, and a marker equal to `collection` applies only there. Empty
/// markers (complete generation) and online callers never refuse.
pub(crate) fn member_schema_incomplete_applies(
    caller: &crate::mcp::registry::Caller,
    collection: &str,
) -> bool {
    caller
        .member_schema_incomplete_for()
        .iter()
        .any(|marker| marker == "global" || marker == collection)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::error::STANDBY_READ_ONLY_CODE;
    use crate::mcp::registry::{Caller, ToolRegistry};
    use crate::member_copy_lifecycle::{MemberCopyLifecycle, ReconnectAnswer, RevokedCause};
    use crate::member_offline_fixtures::assert_no_counter_fields;

    const SCOPE: &str = "scope-ref-1";
    const CUT: &str = "2026-09-29T00:00:00Z";

    fn consumer_identity() -> crate::standby_snapshot::StandbyConsumerIdentity {
        use crate::standby_snapshot::{
            StandbyConsumerIdentity, StandbyConsumerPlatform, STANDBY_CONSUMER_CONTRACT,
        };
        StandbyConsumerIdentity {
            contract: STANDBY_CONSUMER_CONTRACT.to_owned(),
            version: 1,
            platform: StandbyConsumerPlatform::LinuxX8664,
            source_sha: "c".repeat(40),
            artifact_sha256: "d".repeat(64),
            engine_schema_version: 1,
            ddl_sha256: "e".repeat(64),
        }
    }

    fn ready_lifecycle() -> (tempfile::TempDir, Arc<Mutex<MemberCopyLifecycle>>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut lifecycle = MemberCopyLifecycle::open(dir.path()).expect("open");
        lifecycle
            .sign_in("acct", ReconnectAnswer::Replace { cut_at: CUT.into() })
            .expect("sign in");
        lifecycle.mark_refreshed(CUT.into()).expect("refreshed");
        (dir, Arc::new(Mutex::new(lifecycle)))
    }

    fn gate(lifecycle: Arc<Mutex<MemberCopyLifecycle>>) -> MemberCopyGate {
        MemberCopyGate::new(lifecycle, SCOPE.to_owned(), 1, Vec::new())
    }

    /// Build, admit and open a member copy of `source` for `account`, rebuilding
    /// the derived FTS indexes admission needs for search. Returns the
    /// read-only member `Db` and the lifecycle a serving registry gate takes.
    async fn admit_member_copy_of(
        dir: &tempfile::TempDir,
        source: &crate::db::Db,
        account: &str,
        scope_ref: &str,
    ) -> (crate::db::Db, Arc<Mutex<MemberCopyLifecycle>>) {
        use crate::member_copy_admission::{admit_member_copy, ExpectedFooting};

        let staged = dir.path().join(format!("staged-{account}.db"));
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: account.to_owned(),
            scope_ref: scope_ref.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: staged.clone(),
        };
        let copy = crate::member_copy_producer::build_member_copy(source, request)
            .await
            .expect("producer");
        let copy_root = dir.path().join(format!("copy-{account}"));
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let generated_scope = match &copy.manifest.scope {
            crate::holding::ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            crate::holding::ReplicaScope::Everything => panic!("member scope expected"),
        };
        let expected = ExpectedFooting {
            origin_database_id: copy.manifest.origin_database_id.clone(),
            scope_ref: generated_scope,
            consumer: copy.manifest.consumer.clone(),
        };
        let admitted = admit_member_copy(
            &copy_root,
            &staged,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &expected,
            &mut lifecycle,
        )
        .expect("admission");
        let member = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");
        (member, Arc::new(Mutex::new(lifecycle)))
    }

    /// One `search` call through a registry. Dispatch derives `member_copy`
    /// from the `Db` open mode, so an ordinary authenticated caller exercises
    /// the production member path when `db` is a member copy.
    async fn search_value(
        registry: &crate::mcp::registry::ToolRegistry,
        db: &crate::db::Db,
        account: &str,
        query: &str,
    ) -> Value {
        registry
            .call(
                db.clone(),
                crate::mcp::registry::Caller::authenticated(account),
                "search",
                json!({ "query": query }),
            )
            .await
            .expect("search")
    }

    fn assert_refusal_clean(error: &Error) {
        assert_no_counter_fields(&json!({ "message": error.to_string() }), "member refusal");
    }

    #[test]
    fn copy_state_gate_is_typed_for_each_status() {
        // Ready: an allowed surface passes.
        let (_dir, lifecycle) = ready_lifecycle();
        gate(lifecycle)
            .admit(Some(ToolKind::Ping), "ping", &json!({}))
            .expect("ready");

        // Locked.
        let (_dir, lifecycle) = ready_lifecycle();
        lifecycle
            .lock()
            .expect("lock")
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        let error = gate(lifecycle)
            .admit(Some(ToolKind::Ping), "ping", &json!({}))
            .expect_err("locked must refuse");
        assert!(matches!(&error, Error::CopyLocked { retry } if *retry == "after_sign_in"));
        assert_refusal_clean(&error);

        // Removed.
        let (_dir, lifecycle) = ready_lifecycle();
        lifecycle
            .lock()
            .expect("lock")
            .apply_reconnect(ReconnectAnswer::Revoked {
                cause: RevokedCause::MembershipEnded,
            })
            .expect("revoked");
        let error = gate(lifecycle)
            .admit(Some(ToolKind::Ping), "ping", &json!({}))
            .expect_err("removed must refuse");
        assert!(matches!(&error, Error::CopyRemoved { .. }));
        assert_refusal_clean(&error);

        // Unavailable (fresh open, no admitted cut).
        let dir = tempfile::tempdir().expect("tempdir");
        let lifecycle = Arc::new(Mutex::new(
            MemberCopyLifecycle::open(dir.path()).expect("open"),
        ));
        let error = gate(lifecycle)
            .admit(Some(ToolKind::Ping), "ping", &json!({}))
            .expect_err("unavailable must refuse");
        assert!(matches!(&error, Error::CopyUnavailable));
        assert_refusal_clean(&error);
    }

    #[test]
    fn every_unavailable_offline_tool_is_refused() {
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = gate(lifecycle);
        let mut checked = 0;
        for kind in ToolKind::ALL {
            if !matches!(kind.member_scope(), MemberScope::UnavailableOffline) {
                continue;
            }
            let error = gate
                .admit(Some(kind), kind.name(), &json!({}))
                .expect_err("unavailable surface must refuse");
            assert!(
                matches!(&error, Error::UnavailableOffline { surface, requirement }
                    if surface.as_str() == kind.name() && requirement == "surface_unavailable"),
                "{kind:?}: {error:?}"
            );
            assert_refusal_clean(&error);
            checked += 1;
        }
        assert!(checked > 0, "there must be unavailable surfaces to refuse");
    }

    #[test]
    fn every_write_tool_is_refused_read_only() {
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = gate(lifecycle);
        let mut checked = 0;
        for kind in ToolKind::ALL {
            if !matches!(kind.member_scope(), MemberScope::WriteRefused) {
                continue;
            }
            let error = gate
                .admit(Some(kind), kind.name(), &json!({}))
                .expect_err("write must refuse");
            assert!(
                matches!(&error, Error::StandbyReadOnly { code, .. } if *code == STANDBY_READ_ONLY_CODE)
            );
            assert_eq!(error.to_string(), STANDBY_READ_ONLY_CODE);
            assert_refusal_clean(&error);
            checked += 1;
        }
        assert!(checked > 0, "there must be write surfaces to refuse");
    }

    #[test]
    fn mixed_write_actions_and_refused_arguments_are_refused() {
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = gate(lifecycle);

        // A write action of a mixed tool is STANDBY_READ_ONLY.
        for (kind, action) in [
            (ToolKind::ManageAttachments, "detach"),
            (ToolKind::ManageLinks, "add"),
            (ToolKind::ManageLinks, "remove"),
        ] {
            let error = gate
                .admit(Some(kind), kind.name(), &json!({ "action": action }))
                .expect_err("write action must refuse");
            assert!(matches!(error, Error::StandbyReadOnly { .. }), "{kind:?}");
        }
        // The list action is served while add/remove still refuse above.
        gate.admit(
            Some(ToolKind::ManageLinks),
            "manage_links",
            &json!({"action": "list"}),
        )
        .expect("link listing is served");

        // A refused argument refuses before storage, and names the argument.
        let error = gate
            .admit(
                Some(ToolKind::GetRecord),
                "get_record",
                &json!({ "as_of": {"kind": "act", "act": 3} }),
            )
            .expect_err("as_of must refuse");
        assert!(matches!(
            &error,
            Error::UnavailableOffline { requirement, .. } if requirement.as_str() == "as_of"
        ));
        assert_refusal_clean(&error);
        // ...but an absent/`null` refused argument does not: the served
        // surface then passes.
        gate.admit(
            Some(ToolKind::GetRecord),
            "get_record",
            &json!({ "as_of": null }),
        )
        .expect("get_record is served when as_of is absent");
    }

    #[test]
    fn scan_passes_the_gate_now_that_rev8_serves_it() {
        // Rev 8 §2.3(a): scan is served; the per-axis markers live in the
        // response, not in a whole-scan refusal.
        let (_dir, lifecycle) = ready_lifecycle();
        gate(lifecycle)
            .admit(Some(ToolKind::Scan), "scan", &json!({}))
            .expect("scan is a served surface in rev 8");
    }

    #[test]
    fn the_four_trivial_surfaces_pass() {
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = gate(lifecycle);
        for name in MEMBER_SERVED_SURFACES {
            let kind = ToolKind::ALL
                .into_iter()
                .find(|kind| kind.name() == *name)
                .expect("served surface is a real tool");
            gate.admit(Some(kind), name, &json!({}))
                .unwrap_or_else(|error| panic!("{name} must pass: {error:?}"));
        }
    }

    #[test]
    fn scrub_removes_only_known_metadata_positions() {
        let mut value = json!({
            "act": 5,
            "head_act": 7,
            "frontier": {"a": 1},
            "as_of_seq": 9,
            "content_head_seq": 9,
            "previous_seq": 9,
            "local_seq": 1,
            "event_seq": 4,
            "source_event_seq": 2,
            "authorization_revision_epoch": 3,
            "as_of": {"content_seq": 8, "page_digest": "opaque"},
            "acts": [1, 2, 3],
            "records": [{
                "id": "r1",
                "version": "rec:123",
                "name": "rec:123",
                "body": "obs:456",
                "summary": "rec:7",
                "facets": [
                    {"key": "plain", "version": "obs:456", "value": "obs:456"},
                    {"key": "payload", "value": {"seq": 1, "my_seq": 2}}
                ]
            }],
            "ordering": {"kind": "scoped", "ordinal": 3},
            "caller_write_ordinal": 12,
            "revision_digest": "sha256:9f2c"
        });
        scrub_member_response("get_record", &mut value);

        // Real metadata positions are omitted.
        for key in [
            "act",
            "head_act",
            "frontier",
            "as_of_seq",
            "content_head_seq",
            "previous_seq",
            "local_seq",
            "event_seq",
            "source_event_seq",
            "authorization_revision_epoch",
            "acts",
        ] {
            assert!(value.get(key).is_none(), "{key} must be omitted");
        }
        assert!(value["as_of"].get("content_seq").is_none());
        assert_eq!(value["as_of"]["page_digest"], json!("opaque"));
        let record = &value["records"][0];
        assert!(record.get("version").is_none(), "record version omitted");
        assert!(
            record["facets"][0].get("version").is_none(),
            "facet version omitted"
        );

        // Authored payload is preserved verbatim, including counter-like text
        // and authored JSON keys nested in a facet value.
        assert_eq!(record["name"], json!("rec:123"));
        assert_eq!(record["body"], json!("obs:456"));
        assert_eq!(record["summary"], json!("rec:7"));
        assert_eq!(record["facets"][0]["value"], json!("obs:456"));
        assert_eq!(record["facets"][1]["value"], json!({"seq": 1, "my_seq": 2}));

        // Allowed member-scope fields survive.
        assert_no_counter_fields(&value, "scrubbed member response");
        assert_eq!(value["ordering"]["ordinal"], json!(3));
        assert_eq!(value["caller_write_ordinal"], json!(12));
        assert_eq!(value["revision_digest"], json!("sha256:9f2c"));
    }

    #[tokio::test]
    async fn slice_visibility_is_presence_in_the_slice() {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("pool");
        sqlx::query("CREATE TABLE records (id TEXT PRIMARY KEY)")
            .execute(&pool)
            .await
            .expect("table");
        for id in ["r1", "r2"] {
            sqlx::query("INSERT INTO records (id) VALUES (?)")
                .bind(id)
                .execute(&pool)
                .await
                .expect("insert");
        }
        let visible = slice_visible_ids(&pool, vec!["r1".into(), "missing".into()])
            .await
            .expect("fold");
        assert!(visible.contains("r1"));
        assert!(!visible.contains("missing"));
    }

    #[tokio::test]
    async fn dispatch_gate_refuses_before_handler_and_decorates_allowed() {
        let db = crate::db::create_database(":memory:").await.expect("db");
        let mut registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut registry).expect("builtins");
        // Probes whose handlers would return this marker if the gate let them
        // through. Seeing the typed refusal instead proves the gate ran first.
        // `get_history` is permanently `UnavailableOffline`, so it stays a
        // stable unserved probe as later slices serve dashboard/links/attachments;
        // `create_record` is a write.
        for kind in [ToolKind::GetHistory, ToolKind::CreateRecord] {
            registry
                .register(
                    kind,
                    "gate probe",
                    json!({"type": "object"}),
                    |_db, _caller, _args| async move { Ok(json!({"handler": "ran"})) },
                )
                .expect("register probe");
        }
        let (_dir, lifecycle) = ready_lifecycle();
        registry.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());
        let caller = Caller::member_copy("acct");
        assert!(caller.is_member_copy());

        // A served surface runs and is decorated with the member holding.
        let outcome = registry
            .call_detailed(db.clone(), caller.clone(), "ping", json!({}))
            .await
            .expect("ping is served");
        let structured = outcome.outcome.expect("ping ok").structured;
        assert_eq!(structured["ok"], json!(true));
        assert_eq!(
            structured["standby_context"]["contract"],
            json!("native.holding-disclosure.v2")
        );
        assert_eq!(
            structured["standby_context"]["scope"]["kind"],
            json!("member")
        );
        assert_no_counter_fields(&structured, "member ping response");

        // A permanently-unavailable surface is refused before the handler.
        let error = registry
            .call_detailed(db.clone(), caller.clone(), "get_history", json!({}))
            .await
            .err()
            .expect("get_history is never served offline");
        assert!(
            matches!(&error, Error::UnavailableOffline { requirement, .. }
                if requirement.as_str() == "surface_unavailable"),
            "{error:?}"
        );
        assert!(
            !error.to_string().contains("handler"),
            "handler must not run"
        );

        // A write is refused typed, before the handler.
        let error = registry
            .call_detailed(db, caller, "create_record", json!({}))
            .await
            .err()
            .expect("write must refuse");
        assert!(matches!(&error, Error::StandbyReadOnly { .. }), "{error:?}");
        assert_eq!(error.to_string(), STANDBY_READ_ONLY_CODE);
    }

    #[tokio::test]
    async fn member_database_opens_read_only_and_skips_engine_shape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("snapshot.db");
        {
            let connection = rusqlite::Connection::open(&path).expect("member sqlite");
            connection
                .execute_batch(&crate::schema::member_schema::member_ddl_statements().join(";\n"))
                .expect("member ddl");
            connection
                .execute_batch(
                    "INSERT INTO records (id, type, name) VALUES ('r1','Document','one');",
                )
                .expect("seed");
        }
        // The member file has no engine shape; the canonical open would refuse.
        assert!(
            crate::db::open_existing_database(path.to_str().expect("path"))
                .await
                .is_err(),
            "the canonical engine open must refuse a member-read-v1 file"
        );
        let db = crate::db::open_member_database_read_only(path.to_str().expect("path"))
            .await
            .expect("member open");
        assert_eq!(db.open_mode(), crate::db::DatabaseOpenMode::MemberReadOnly);
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM records")
            .fetch_one(db.write_pool())
            .await
            .expect("read");
        assert_eq!(count, 1);
        assert!(
            sqlx::query("INSERT INTO records (id, type, name) VALUES ('r2','Document','two')")
                .execute(db.write_pool())
                .await
                .is_err(),
            "a member copy is physically read-only"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn member_database_open_refuses_a_non_member_sqlite() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("plain.db");
        {
            let connection = rusqlite::Connection::open(&path).expect("sqlite");
            connection
                .execute_batch("CREATE TABLE records (id TEXT PRIMARY KEY);")
                .expect("table");
        }
        assert!(
            crate::db::open_member_database_read_only(path.to_str().expect("path"))
                .await
                .is_err(),
            "a non-member sqlite must not open as a member copy"
        );
    }

    #[tokio::test]
    async fn member_database_open_refuses_a_canonical_only_table() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("with-canonical.db");
        {
            let connection = rusqlite::Connection::open(&path).expect("sqlite");
            connection
                .execute_batch(&crate::schema::member_schema::member_ddl_statements().join(";\n"))
                .expect("member ddl");
            // A canonical-only table smuggled into an otherwise member-shaped
            // file (the marker table is present).
            connection
                .execute_batch("CREATE TABLE policy_entries (policy_anchor_id TEXT);")
                .expect("canonical table");
        }
        assert!(
            crate::db::open_member_database_read_only(path.to_str().expect("path"))
                .await
                .is_err(),
            "a canonical-only table must refuse the member open"
        );
    }

    #[test]
    fn refusal_is_identical_for_hidden_and_absent_ids() {
        // An excluded history surface is refused before any id resolution, so a
        // hidden id and a never-existed id get the same typed refusal: the
        // gate never probes the slice (contract R1/R4).
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = gate(lifecycle);
        let hidden = gate
            .admit(
                Some(ToolKind::GetHistory),
                "get_history",
                &json!({"filter": {"field": "id", "op": "eq", "value": "hidden-id"}}),
            )
            .expect_err("hidden id must refuse");
        let absent = gate
            .admit(
                Some(ToolKind::GetHistory),
                "get_history",
                &json!({"filter": {"field": "id", "op": "eq", "value": "never-existed"}}),
            )
            .expect_err("absent id must refuse");
        assert_eq!(hidden.to_string(), absent.to_string());
        assert!(matches!(
            hidden,
            Error::UnavailableOffline { ref surface, ref requirement }
                if surface == "get_history" && requirement == "surface_unavailable"
        ));
        assert!(!hidden.to_string().contains("hidden-id"));
        assert!(!hidden.to_string().contains("never-existed"));
    }

    #[tokio::test]
    async fn member_visibility_fold_is_slice_presence_not_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("member.db");
        {
            let connection = rusqlite::Connection::open(&path).expect("sqlite");
            connection
                .execute_batch(&crate::schema::member_schema::member_ddl_statements().join(";\n"))
                .expect("member ddl");
            connection
                .execute_batch(
                    "INSERT INTO records (id, type, name) VALUES ('r1','Document','one');",
                )
                .expect("seed");
        }
        let db = crate::db::open_member_database_read_only(path.to_str().expect("path"))
            .await
            .expect("member open");
        // The member file has no policy/Unit tables; the fold must succeed by
        // slice presence rather than degrading on the missing tables.
        let visible = crate::mcp::tools::visible_ids_in_pool(
            db.write_pool(),
            &Caller::member_copy("acct"),
            vec!["r1".into(), "missing".into()],
        )
        .await
        .expect("member visibility fold");
        assert!(visible.contains("r1"));
        assert!(!visible.contains("missing"));
        db.close().await;
    }

    #[tokio::test]
    async fn producer_copy_pipeline_slice_is_e_m_and_fold_matches() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer must build a member copy");
        assert_eq!(copy.content_digest.len(), 64);
        let db = crate::db::open_member_database_read_only(member_path.to_str().expect("path"))
            .await
            .expect("member open");

        // No hidden id is visible through the member-safe fold.
        let hidden = two_caller::hidden_from_a()
            .iter()
            .map(|id| (*id).to_owned())
            .collect::<Vec<_>>();
        assert!(!hidden.is_empty(), "the world must hide something from A");
        let hidden_fold = crate::mcp::tools::visible_ids_in_pool(
            db.write_pool(),
            &Caller::member_copy(ACCT_A),
            hidden,
        )
        .await
        .expect("fold");
        assert!(
            hidden_fold.is_empty(),
            "no hidden id may be visible in A's slice: {hidden_fold:?}"
        );

        // The slice contains A's visible records.
        let visible = two_caller::visible_to_a()
            .iter()
            .map(|id| (*id).to_owned())
            .collect::<Vec<_>>();
        let visible_fold = crate::mcp::tools::visible_ids_in_pool(
            db.write_pool(),
            &Caller::member_copy(ACCT_A),
            visible,
        )
        .await
        .expect("fold");
        assert!(
            !visible_fold.is_empty(),
            "A's slice must contain visible records"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn single_reader_serves_visible_slice_and_hides_hidden() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use crate::query::lens::ReadLens;
        use crate::query::read::{get_record_with_lens_as, EnrichOptions};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let _copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        let member_db =
            crate::db::open_member_database_read_only(member_path.to_str().expect("path"))
                .await
                .expect("member open");

        let opts = EnrichOptions::default();
        let online = get_record_with_lens_as(
            &ReadLens::live(&world.db),
            two_caller::SHARED_CHILD,
            opts,
            crate::authorization::Principal::bound(ACCT_A, true),
        )
        .await
        .expect("online read")
        .expect("shared child is visible online");
        let offline = get_record_with_lens_as(
            &ReadLens::live(&member_db),
            two_caller::SHARED_CHILD,
            opts,
            crate::authorization::Principal::bound(ACCT_A, true),
        )
        .await
        .expect("offline read")
        .expect("shared child is visible offline");
        // Core record fields are parity.
        assert_eq!(offline.record.id, online.record.id);
        assert_eq!(offline.record.name, online.record.name);
        assert_eq!(offline.record.body, online.record.body);
        assert_eq!(offline.record.record_type, online.record.record_type);
        // §2.6: every member facet version is omitted.
        for facet in &offline.facets {
            assert!(
                facet.version.is_none(),
                "member facet version must be omitted"
            );
        }

        // A hidden id is absent offline, exactly like a never-existed id.
        let hidden = get_record_with_lens_as(
            &ReadLens::live(&member_db),
            two_caller::B_ONLY,
            opts,
            crate::authorization::Principal::bound(ACCT_A, true),
        )
        .await
        .expect("offline hidden read");
        let absent = get_record_with_lens_as(
            &ReadLens::live(&member_db),
            "ffffffff-0000-4000-8000-ffffffffffff",
            opts,
            crate::authorization::Principal::bound(ACCT_A, true),
        )
        .await
        .expect("offline absent read");
        assert!(hidden.is_none(), "a hidden id must be absent offline");
        assert!(
            absent.is_none(),
            "a never-existed id must be absent offline"
        );
        member_db.close().await;
    }

    /// Strip §2.6 omissions and §2.3 marker sections so the remaining
    /// slice-derived fields can be compared for parity.
    fn normalize_record(item: &mut Value) {
        let Some(object) = item.as_object_mut() else {
            return;
        };
        for key in [
            "version",
            "contribution",
            "custody_boundary",
            "target",
            "history_summary",
            "citations",
            "communication_origin",
            "federation_provenance",
            "mentions_out",
            "mentions_in",
            "message_expectation_state",
            "query_resolution",
            // R1 carve-out: offline counts visible (slice) successors only,
            // online counts invisible successors until e5f171c; compared
            // separately, never for equality here.
            "superseded_by",
        ] {
            object.remove(key);
        }
    }

    #[tokio::test]
    async fn member_get_record_is_parity_with_markers() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let _copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        let member_db =
            crate::db::open_member_database_read_only(member_path.to_str().expect("path"))
                .await
                .expect("member open");

        let mut online_registry = ToolRegistry::new();
        register_builtin_tools(&mut online_registry).expect("builtins");
        register_surface_tools(&mut online_registry).expect("surface");

        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        lifecycle.mark_refreshed(CUT.to_owned()).expect("refresh");
        let mut member_registry = ToolRegistry::new();
        register_builtin_tools(&mut member_registry).expect("builtins");
        register_surface_tools(&mut member_registry).expect("surface");
        member_registry.set_member_copy_gate(
            std::sync::Arc::new(std::sync::Mutex::new(lifecycle)),
            SCOPE.to_owned(),
            1,
            Vec::new(),
        );

        let arguments = json!({ "ids": [two_caller::SHARED_CHILD] });
        let mut online = online_registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                arguments.clone(),
            )
            .await
            .expect("online get_record");
        let mut offline = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "get_record",
                arguments,
            )
            .await
            .expect("member get_record");

        assert_no_counter_fields(&offline, "member get_record");
        let offline_marker = offline["records"][0]["contribution"].clone();
        assert_eq!(offline["records"][0]["status"], json!("found"));
        assert_eq!(
            offline_marker["unavailable_offline"]["surface"],
            json!("contribution"),
            "contribution must be a marker: {offline_marker}"
        );
        assert!(offline["records"][0]["custody_boundary"]["unavailable_offline"].is_object());
        assert!(
            offline["records"][0].get("target").is_none(),
            "a non-citation record carries no citation target marker"
        );
        assert!(
            offline["records"][0].get("version").is_none(),
            "version omitted"
        );
        normalize_record(&mut online["records"][0]);
        normalize_record(&mut offline["records"][0]);
        assert_eq!(
            online["records"][0], offline["records"][0],
            "member get_record must be parity after normalization"
        );

        // A hidden id is absent, exactly like a never-existed id.
        let hidden = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "get_record",
                json!({ "ids": [two_caller::B_ONLY] }),
            )
            .await
            .expect("member hidden get_record");
        assert_eq!(hidden["records"][0]["status"], json!("not_found"));

        // render_record markdown is parity for a visible record.
        let online_render = online_registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "render_record",
                json!({ "id": two_caller::SHARED_CHILD }),
            )
            .await
            .expect("online render_record");
        let offline_render = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "render_record",
                json!({ "id": two_caller::SHARED_CHILD }),
            )
            .await
            .expect("member render_record");
        assert_no_counter_fields(&offline_render, "member render_record");
        assert_eq!(
            online_render["markdown"], offline_render["markdown"],
            "render_record markdown must be parity"
        );
        let interpreted = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "render_record",
                json!({ "id": two_caller::SHARED_CHILD, "include_interpretation": true }),
            )
            .await
            .expect("member render_record interpretation");
        assert!(interpreted["interpretation"]["unavailable_offline"].is_object());

        member_db.close().await;
    }

    #[tokio::test]
    async fn member_differential_seed_cases_and_oracle() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{online_visible_ids, two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let _copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        let member_db =
            crate::db::open_member_database_read_only(member_path.to_str().expect("path"))
                .await
                .expect("member open");

        let mut online_registry = ToolRegistry::new();
        register_builtin_tools(&mut online_registry).expect("builtins");
        register_surface_tools(&mut online_registry).expect("surface");
        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        lifecycle.mark_refreshed(CUT.to_owned()).expect("refresh");
        let mut member_registry = ToolRegistry::new();
        register_builtin_tools(&mut member_registry).expect("builtins");
        register_surface_tools(&mut member_registry).expect("surface");
        member_registry.set_member_copy_gate(
            std::sync::Arc::new(std::sync::Mutex::new(lifecycle)),
            SCOPE.to_owned(),
            1,
            Vec::new(),
        );

        // Independent oracle: the engine evaluator on the SOURCE database.
        let oracle = online_visible_ids(&world.db, ACCT_A).await;

        let seeds = [
            (two_caller::VISIBLE_CHILD, "hidden_parent"),
            (two_caller::A_OWNED, "custody"),
            (two_caller::MSG_A, "message"),
            (two_caller::OLD_RECORD, "hidden_successor"),
            // A record in the visible collection whose scoped schema row was
            // withheld by the exact-id gate (`GATED_COLL_SCHEMA` on SHARED).
            (two_caller::SHARED_CHILD, "schema_gated"),
        ];
        for (id, label) in seeds {
            let mut online = online_registry
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_A),
                    "get_record",
                    json!({ "ids": [id] }),
                )
                .await
                .expect("online");
            let mut offline = member_registry
                .call(
                    member_db.clone(),
                    Caller::member_copy(ACCT_A),
                    "get_record",
                    json!({ "ids": [id] }),
                )
                .await
                .expect("offline");
            assert_no_counter_fields(&offline, "member seed get_record");
            assert_eq!(offline["records"][0]["status"], json!("found"), "{label}");
            assert!(
                oracle.contains(id),
                "served {id} must be in the E(m) oracle ({label})"
            );
            if label == "custody" {
                assert!(
                    offline["records"][0]["custody_boundary"]["unavailable_offline"].is_object()
                );
            }
            if label == "message" {
                for key in [
                    "communication_origin",
                    "message_expectation_state",
                    "mentions_out",
                ] {
                    assert!(
                        offline["records"][0][key]["unavailable_offline"].is_object(),
                        "message {key} must be a marker"
                    );
                }
            }
            if label == "hidden_successor" {
                if let Some(items) = offline["records"][0]["superseded_by"]["items"].as_array() {
                    for successor in items {
                        let sid = successor["id"].as_str().expect("successor id");
                        assert!(
                            oracle.contains(sid),
                            "offline successor {sid} must be visible in the oracle"
                        );
                    }
                }
            }
            normalize_record(&mut online["records"][0]);
            normalize_record(&mut offline["records"][0]);
            assert_eq!(
                online["records"][0], offline["records"][0],
                "seed parity for {label}"
            );
        }

        // Every E(m) oracle id is servable offline, and every served id is in
        // the oracle.
        for id in &oracle {
            let offline = member_registry
                .call(
                    member_db.clone(),
                    Caller::member_copy(ACCT_A),
                    "get_record",
                    json!({ "ids": [id] }),
                )
                .await
                .expect("offline oracle");
            assert_eq!(
                offline["records"][0]["status"],
                json!("found"),
                "oracle id {id} must be servable"
            );
        }

        member_db.close().await;
    }

    #[tokio::test]
    async fn overshipped_hidden_row_is_caught_by_the_differential() {
        use crate::holding::ReplicaScope;
        use crate::mcp::registry::Caller;
        use crate::member_copy_admission::{admit_member_copy, ExpectedFooting};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use sha2::Digest as _;

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: staged.clone(),
        };
        let mut copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");

        // Plant a hidden record (B_ONLY) plus a link to it, then fix the
        // content digest and byte identity so admission accepts the oversized
        // slice. This is the wrong-slice defect the differential must catch.
        {
            let connection = rusqlite::Connection::open(&staged).expect("sqlite");
            connection
                .execute_batch(&format!(
                    "INSERT INTO records (id, type, kind, name, body, persistence, created_at, updated_at, archived) \
                     VALUES ('{}','Document','note','{}','b-only note','enduring','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0); \
                     INSERT INTO links (id, source_id, target_id, relationship, created_at) \
                     VALUES ('overship-link','{}','{}','ref','2026-01-01T00:00:00Z');",
                    two_caller::B_ONLY,
                    two_caller::B_ONLY,
                    two_caller::SHARED_CHILD,
                    two_caller::B_ONLY
                ))
                .expect("plant hidden row");
            let digest = crate::member_digest::content_digest(&connection).expect("digest");
            drop(connection);
            copy.content_digest = digest.clone();
            copy.manifest.content_digest = digest;
            let bytes = std::fs::read(&staged).expect("bytes");
            copy.manifest.bytes.size_bytes = bytes.len() as u64;
            copy.manifest.bytes.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        }

        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let scope_ref = match &copy.manifest.scope {
            ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            ReplicaScope::Everything => panic!("producer copy is a member scope"),
        };
        let expected = ExpectedFooting {
            origin_database_id: copy.manifest.origin_database_id.clone(),
            scope_ref,
            consumer: copy.manifest.consumer.clone(),
        };
        let admitted = admit_member_copy(
            &copy_root,
            &staged,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &expected,
            &mut lifecycle,
        )
        .expect("admission accepts the digest-fixed oversized slice");
        let member_db = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");

        let served = crate::mcp::tools::lifecycle::get_record(
            member_db.clone(),
            Caller::member_copy(ACCT_A),
            json!({ "ids": [two_caller::B_ONLY] }),
        )
        .await
        .expect("member get_record");
        let online = crate::mcp::tools::lifecycle::get_record(
            world.db.clone(),
            Caller::authenticated(ACCT_A),
            json!({ "ids": [two_caller::B_ONLY] }),
        )
        .await
        .expect("online get_record");
        assert_eq!(
            served["records"][0]["status"],
            json!("found"),
            "the over-shipped hidden row is served (the defect)"
        );
        assert_eq!(online["records"][0]["status"], json!("not_found"));
        assert_ne!(
            online["records"][0]["status"], served["records"][0]["status"],
            "the differential must detect an over-shipped hidden row"
        );
        assert_no_counter_fields(&served, "overshipped response");

        // Search must detect the over-shipped row too.
        let served_search = crate::mcp::tools::querying::search(
            member_db.clone(),
            Caller::member_copy(ACCT_A),
            json!({ "query": "b-only" }),
        )
        .await
        .expect("member search");
        let online_search = crate::mcp::tools::querying::search(
            world.db.clone(),
            Caller::authenticated(ACCT_A),
            json!({ "query": "b-only" }),
        )
        .await
        .expect("online search");
        let search_ids = |value: &Value| -> Vec<String> {
            value["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .map(|hit| hit["id"].as_str().expect("hit id").to_owned())
                .collect()
        };
        assert!(search_ids(&served_search).contains(&two_caller::B_ONLY.to_owned()));
        assert!(!search_ids(&online_search).contains(&two_caller::B_ONLY.to_owned()));
        assert_ne!(
            search_ids(&served_search),
            search_ids(&online_search),
            "search differential must detect an over-shipped hidden row"
        );
        assert_no_counter_fields(&served_search, "overshipped search");
        member_db.close().await;
    }

    #[tokio::test]
    async fn online_output_carries_no_member_markers() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).expect("builtins");
        register_surface_tools(&mut registry).expect("surface");
        let record = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                json!({ "ids": [two_caller::SHARED_CHILD] }),
            )
            .await
            .expect("online get_record");
        assert!(
            !record.to_string().contains("unavailable_offline"),
            "online get_record must not emit member markers"
        );
        assert!(
            record["records"][0]["version"].is_string(),
            "online get_record keeps the record version"
        );
        let rendered = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "render_record",
                json!({ "id": two_caller::SHARED_CHILD }),
            )
            .await
            .expect("online render_record");
        assert!(
            !rendered.to_string().contains("unavailable_offline"),
            "online render_record must not emit member markers"
        );
    }

    /// F2 (C2c-1 review): every member branch is `if member {…} else
    /// {unchanged}`, so an online call that takes each else leg must return the
    /// online shape — a `rec:`/`obs:` token, a real bool, a resolved section —
    /// not an omitted field or a marker. This is branch coverage; the smoke
    /// test above only scans for the marker substring.
    #[tokio::test]
    async fn online_reads_keep_every_shape_the_member_branches_replace() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A, ACCT_B};
        use crate::schema::ROOT_RECORD_ID;

        let world = two_caller::build().await;
        let mut registry = ToolRegistry::new();
        register_builtin_tools(&mut registry).expect("builtins");
        register_surface_tools(&mut registry).expect("surface");

        // read.rs auth branch: online the hidden id is refused by the policy
        // fold, never found through slice presence.
        for (account, hidden) in [
            (ACCT_A, two_caller::B_ONLY),
            (ACCT_B, two_caller::HIDDEN_PARENT),
        ] {
            let record = registry
                .call(
                    world.db.clone(),
                    Caller::authenticated(account),
                    "get_record",
                    json!({ "ids": [hidden] }),
                )
                .await
                .expect("online hidden get_record");
            assert_eq!(
                record["records"][0]["status"],
                json!("not_found"),
                "{hidden} must be hidden from {account} by policy"
            );
        }

        // read.rs facet-version and record-version branches: online keeps both
        // `obs:` and `rec:` tokens (the member answer omits them, §2.6).
        let facet_record = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                json!({ "ids": [two_caller::HIDDEN_PARENT] }),
            )
            .await
            .expect("facet record");
        let item = &facet_record["records"][0];
        assert!(
            item["version"]
                .as_str()
                .is_some_and(|version| version.starts_with("rec:")),
            "online keeps the record version: {item}"
        );
        assert!(
            item["facets"]
                .as_array()
                .expect("facets")
                .iter()
                .filter_map(|facet| facet["version"].as_str())
                .any(|version| version.starts_with("obs:")),
            "online keeps a facet obs: version: {item}"
        );

        // lifecycle.rs custody/contribution branches: online custody is a real
        // bool and contribution is a projection, never a marker.
        assert!(item["custody_boundary"].is_boolean(), "{item}");
        assert!(
            item.get("contribution")
                .is_none_or(|c| c.get("unavailable_offline").is_none()),
            "online contribution must not be a marker: {item}"
        );

        // read.rs hydrate_communication_origin branch and the lifecycle
        // supplement branches: an online Message keeps its audience,
        // provenance, mentions and expectation state rather than markers.
        let message = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                json!({ "ids": [two_caller::MSG_A] }),
            )
            .await
            .expect("message");
        let message = &message["records"][0];
        for key in [
            "communication_origin",
            "federation_provenance",
            "mentions_out",
            "mentions_in",
            "message_expectation_state",
        ] {
            assert!(
                message[key].get("unavailable_offline").is_none(),
                "online message {key} must not be a marker: {message}"
            );
        }

        // read.rs citation-target branch: online resolves the target of an
        // Annotation that carries an `annotation_targets` row. The member
        // answer is the citation marker (covered by the marker test), never a
        // silent None.
        let citation_id = "c17a7000-0000-4000-8000-0000000000f1";
        crate::store::create_record(
            &world.db,
            json!({
                "id": citation_id,
                "type": "Annotation",
                "kind": "citation",
                "name": "citation record",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .expect("citation record");
        crate::member_offline_fixtures::grant(
            &world.db,
            citation_id,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        // An Annotation authorizes through its exactly-one `part_of` bearer.
        crate::store::add_link(
            &world.db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: citation_id.into(),
                target_id: two_caller::SHARED_CHILD.into(),
                relationship: "part_of".into(),
                note: None,
            },
        )
        .await
        .expect("citation bearer link");
        sqlx::query(
            "INSERT INTO annotation_targets
               (annotation_id, target_record_id, source_slot, source_event_seq,
                source_sha256, selectors, purpose, created_at, updated_at)
             VALUES (?, ?, 'body',
                     (SELECT COALESCE(MAX(seq), 1) FROM content_events
                       WHERE record_id = ?),
                     'abc', '[]', NULL,
                     '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .bind(citation_id)
        .bind(two_caller::SHARED_CHILD)
        .bind(two_caller::SHARED_CHILD)
        .execute(world.db.write_pool())
        .await
        .expect("annotation target row");
        let citation = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                json!({ "ids": [citation_id] }),
            )
            .await
            .expect("online citation get_record");
        assert_eq!(citation["records"][0]["status"], json!("found"));
        assert!(
            !citation["records"][0]["target"].is_null(),
            "online citation target must resolve: {citation}"
        );

        // render_record short-circuit: online still resolves the opt-in
        // interpretation projection and emits no marker.
        let rendered = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "render_record",
                json!({ "id": two_caller::SHARED_CHILD, "include_interpretation": true }),
            )
            .await
            .expect("online render_record");
        assert!(rendered.get("interpretation").is_some());
        assert!(
            !rendered["markdown"]
                .as_str()
                .expect("markdown")
                .contains("unavailable_offline"),
            "online render markdown must not carry member markers"
        );

        // Online search keeps the policy view predicate: a hidden record's
        // body is not a hit even though the member branch would also exclude
        // it. If the member branch leaked into this path, B_ONLY would appear.
        let hidden_search = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "search",
                json!({ "query": "b-only" }),
            )
            .await
            .expect("online hidden search");
        assert_eq!(hidden_search["total"], json!(0));
        assert!(!hidden_search.to_string().contains(two_caller::B_ONLY));

        // The Q6c display-reference branch: online recomputes a short
        // reference in its own prefix group; the member path substitutes the
        // shipped value. The fixture ids are near-sequential (a hidden sibling
        // saturates the prefix), so use a distinct id that actually mints.
        let minted_id = "0a1b2c3d-0000-4000-8000-0000000000aa";
        crate::member_offline_fixtures::mk_doc(
            &world.db,
            minted_id,
            ROOT_RECORD_ID,
            Some("mintedterm"),
            None,
        )
        .await;
        crate::member_offline_fixtures::grant(
            &world.db,
            minted_id,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        let search = registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "search",
                json!({ "query": "mintedterm" }),
            )
            .await
            .expect("online search");
        assert!(
            search["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .any(|hit| hit["display_reference"].as_str().is_some()),
            "online search recomputes a display reference: {search}"
        );
    }

    #[tokio::test]
    async fn member_flag_is_derived_from_the_db_open_mode() {
        use crate::mcp::registry::{Caller, ToolRegistry};

        let mut registry = ToolRegistry::new();
        registry
            .register(
                ToolKind::ReadGuide,
                "derivation probe",
                json!({"type": "object"}),
                |_db, caller, _args| async move { Ok(json!({"member_copy": caller.is_member_copy()})) },
            )
            .expect("register probe");

        let engine = crate::db::create_database(":memory:")
            .await
            .expect("engine db");
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("member.db");
        {
            let connection = rusqlite::Connection::open(&path).expect("sqlite");
            connection
                .execute_batch(&crate::schema::member_schema::member_ddl_statements().join(";\n"))
                .expect("member ddl");
        }
        let member = crate::db::open_member_database_read_only(path.to_str().expect("path"))
            .await
            .expect("member open");
        // D1: a member-copy Db is served only behind a validated, installed
        // serving gate. Install a Ready one so the dispatch is admitted; the
        // caller-flag derivation under test is unchanged.
        let (_lifecycle_dir, lifecycle) = ready_lifecycle();
        registry.set_member_copy_gate(lifecycle, "scope-ref".to_owned(), 1, Vec::new());

        // A member-copy Db always yields a member caller, even for an ordinary
        // authenticated caller (the production member-serving case).
        let via_member = registry
            .call(
                member.clone(),
                Caller::authenticated("acct"),
                "read_guide",
                json!({}),
            )
            .await
            .expect("member dispatch");
        assert_eq!(
            via_member["member_copy"],
            json!(true),
            "a member Db must mark the caller as member"
        );
        // A non-member Db never yields a member caller, even if the caller was
        // constructed as one.
        let via_engine = registry
            .call(
                engine.clone(),
                Caller::member_copy("acct"),
                "read_guide",
                json!({}),
            )
            .await
            .expect("engine dispatch");
        assert_eq!(
            via_engine["member_copy"],
            json!(false),
            "a non-member Db must never mark the caller as member"
        );
        member.close().await;
        engine.close().await;
    }

    #[tokio::test]
    async fn member_hidden_successor_counts_visible_successors_only() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_B};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member-b.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_B.to_owned(),
            scope_ref: "scope-ref-b".to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let _copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        let member_db =
            crate::db::open_member_database_read_only(member_path.to_str().expect("path"))
                .await
                .expect("member open");

        let mut online_registry = ToolRegistry::new();
        register_builtin_tools(&mut online_registry).expect("builtins");
        register_surface_tools(&mut online_registry).expect("surface");
        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        lifecycle.mark_refreshed(CUT.to_owned()).expect("refresh");
        let mut member_registry = ToolRegistry::new();
        register_builtin_tools(&mut member_registry).expect("builtins");
        register_surface_tools(&mut member_registry).expect("surface");
        member_registry.set_member_copy_gate(
            std::sync::Arc::new(std::sync::Mutex::new(lifecycle)),
            "scope-ref-b".to_owned(),
            1,
            Vec::new(),
        );

        let superseded_ids = |value: &Value| -> Vec<String> {
            value["records"][0]["superseded_by"]["items"]
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|item| item["id"].as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default()
        };
        let online = online_registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "get_record",
                json!({ "ids": [two_caller::OLD_RECORD] }),
            )
            .await
            .expect("online get_record");
        let offline = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_B),
                "get_record",
                json!({ "ids": [two_caller::OLD_RECORD] }),
            )
            .await
            .expect("member get_record");
        assert_no_counter_fields(&offline, "member hidden-successor get_record");
        // Online counts the invisible successor in `total_count` but never
        // names it in `items` (R1 carve-out: offline counts visible/slice
        // successors only).
        assert!(
            online["records"][0]["superseded_by"]["total_count"]
                .as_i64()
                .unwrap_or(0)
                >= 1,
            "online counts the invisible successor: {online}"
        );
        assert!(
            offline["records"][0]["superseded_by"].is_null()
                || offline["records"][0]["superseded_by"]["total_count"]
                    .as_i64()
                    .unwrap_or(0)
                    == 0,
            "offline counts visible successors only: {offline}"
        );
        assert!(
            !superseded_ids(&offline).contains(&two_caller::NEWER_HIDDEN.to_owned()),
            "offline must not name a hidden successor: {offline}"
        );
        member_db.close().await;
    }

    #[tokio::test]
    async fn member_bears_shape_runs_and_is_false() {
        // Surrogate for the deferred unit-bearer case: a shape-bearing record
        // reads `bears_shape = false` on the member Db because its scoped
        // schema row was withheld by the exact-id gate. `bears_shape_in_pool`
        // reads only the shipped `schema_config`, so no excluded table is
        // touched and the unit-bearer deferral stays safe.
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use crate::query::lens::ReadLens;
        use crate::query::read::{get_record_with_lens_as, EnrichOptions};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let _copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        let member_db =
            crate::db::open_member_database_read_only(member_path.to_str().expect("path"))
                .await
                .expect("member open");

        let opts = EnrichOptions::default();
        let online = get_record_with_lens_as(
            &ReadLens::live(&world.db),
            two_caller::VISIBLE_CHILD,
            opts,
            crate::authorization::Principal::bound(ACCT_A, true),
        )
        .await
        .expect("online read")
        .expect("visible child online");
        let offline = get_record_with_lens_as(
            &ReadLens::live(&member_db),
            two_caller::VISIBLE_CHILD,
            opts,
            crate::authorization::Principal::bound(ACCT_A, true),
        )
        .await
        .expect("offline read")
        .expect("visible child offline");
        // `bears_shape_in_pool` reads only the shipped `schema_config`; no seed
        // is unit-borne, so it is false on both and never touches an excluded
        // table. This is the surrogate for the deferred unit-bearer proof.
        assert!(!online.bears_shape, "no scoped schema row applies");
        assert!(
            !offline.bears_shape,
            "member bears_shape must run and be false"
        );
        member_db.close().await;
    }

    #[test]
    fn global_schema_incomplete_refuses_record_readers() {
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = MemberCopyGate::new(lifecycle, SCOPE.to_owned(), 1, vec!["global".to_owned()]);
        // A global withheld row refuses every schema-dependent surface, not
        // just the record readers: the four named schema tools and
        // `open_collection` enrichment are unanswerable too.
        for (kind, name) in [
            (ToolKind::GetRecord, "get_record"),
            (ToolKind::RenderRecord, "render_record"),
            (ToolKind::DescribeSchema, "describe_schema"),
            (ToolKind::PreviewRecordShape, "preview_record_shape"),
            (ToolKind::ResolveFacets, "resolve_facets"),
            (ToolKind::SuggestFacetValues, "suggest_facet_values"),
        ] {
            let error = gate
                .admit(Some(kind), name, &json!({}))
                .expect_err("a global withheld schema row must refuse the surface");
            assert!(
                matches!(
                    &error,
                    Error::UnavailableOffline { requirement, .. } if requirement == "schema_incomplete"
                ),
                "{name}: {error:?}"
            );
            assert_refusal_clean(&error);
        }
        let error = gate
            .admit(
                Some(ToolKind::OpenCollection),
                "open_collection",
                &json!({"id": SCOPE}),
            )
            .expect_err("global must refuse open_collection");
        assert!(matches!(
            &error,
            Error::UnavailableOffline { requirement, .. } if requirement == "schema_incomplete"
        ));
        assert_refusal_clean(&error);
        let error = gate
            .admit(Some(ToolKind::GetDashboard), "get_dashboard", &json!({}))
            .expect_err("withheld global lifecycle governance refuses the dashboard");
        assert!(matches!(
            &error,
            Error::UnavailableOffline { requirement, .. } if requirement == "schema_incomplete"
        ));
        assert_refusal_clean(&error);

        // A collection-scoped marker refuses `open_collection` only for the
        // marked collection; another visible collection stays usable.
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = MemberCopyGate::new(
            lifecycle,
            SCOPE.to_owned(),
            1,
            vec!["collection-marked".to_owned()],
        );
        let error = gate
            .admit(
                Some(ToolKind::OpenCollection),
                "open_collection",
                &json!({"id": "collection-marked"}),
            )
            .expect_err("the marked collection must refuse");
        assert!(matches!(
            &error,
            Error::UnavailableOffline { requirement, .. } if requirement == "schema_incomplete"
        ));
        gate.admit(
            Some(ToolKind::OpenCollection),
            "open_collection",
            &json!({"id": "collection-unrelated"}),
        )
        .expect("an unrelated visible collection must remain usable");
        // The record reader is not collection-scoped at the gate; the
        // record-targeted schema tools refine it in their member branch.
        gate.admit(Some(ToolKind::GetRecord), "get_record", &json!({}))
            .expect("a collection-scoped marker serves the record reader");
    }

    #[test]
    fn query_sql_schema_config_carries_the_schema_gate() {
        // A complete generation serves a `schema_config` read.
        let (_dir, lifecycle) = ready_lifecycle();
        gate(lifecycle)
            .admit(
                Some(ToolKind::QuerySql),
                "query_sql",
                &json!({"sql": "SELECT id FROM schema_config"}),
            )
            .expect("a complete generation serves schema_config");

        // A withheld schema row makes the shipped relation non-authoritative:
        // reading it refuses typed; an unrelated relation still serves.
        let (_dir, lifecycle) = ready_lifecycle();
        let gate = MemberCopyGate::new(
            lifecycle,
            SCOPE.to_owned(),
            1,
            vec!["collection-marked".to_owned()],
        );
        let error = gate
            .admit(
                Some(ToolKind::QuerySql),
                "query_sql",
                &json!({"sql": "SELECT id FROM schema_config"}),
            )
            .expect_err("schema_config read must refuse when the gate withheld a row");
        assert!(
            matches!(&error, Error::UnavailableOffline { requirement, .. } if requirement == "schema_config"),
            "{error:?}"
        );
        assert_refusal_clean(&error);
        gate.admit(
            Some(ToolKind::QuerySql),
            "query_sql",
            &json!({"sql": "SELECT id FROM records"}),
        )
        .expect("an unrelated relation is unaffected");
        // A same-named alias is authored text, not a relation read.
        gate.admit(
            Some(ToolKind::QuerySql),
            "query_sql",
            &json!({"sql": "SELECT 1 AS schema_config"}),
        )
        .expect("an authored alias is not a schema_config read");
    }

    #[tokio::test]
    async fn member_search_is_parity_and_hides_hidden() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let member_path = dir.path().join("member.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: member_path.clone(),
        };
        let copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let scope_ref = match &copy.manifest.scope {
            crate::holding::ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            crate::holding::ReplicaScope::Everything => panic!("member scope"),
        };
        let expected = crate::member_copy_admission::ExpectedFooting {
            origin_database_id: copy.manifest.origin_database_id.clone(),
            scope_ref,
            consumer: copy.manifest.consumer.clone(),
        };
        // Admission rebuilds the derived FTS indexes the search path needs.
        let admitted = crate::member_copy_admission::admit_member_copy(
            &copy_root,
            &member_path,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &expected,
            &mut lifecycle,
        )
        .expect("admission");
        let member_db = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");

        let mut online_registry = ToolRegistry::new();
        register_builtin_tools(&mut online_registry).expect("builtins");
        register_surface_tools(&mut online_registry).expect("surface");
        let mut member_registry = ToolRegistry::new();
        register_builtin_tools(&mut member_registry).expect("builtins");
        register_surface_tools(&mut member_registry).expect("surface");
        member_registry.set_member_copy_gate(
            std::sync::Arc::new(std::sync::Mutex::new(lifecycle)),
            SCOPE.to_owned(),
            1,
            Vec::new(),
        );

        let hit_ids = |value: &Value| -> Vec<String> {
            value["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .map(|hit| hit["id"].as_str().expect("hit id").to_owned())
                .collect()
        };

        // A visible query: ranking/order parity.
        let query = two_caller::VISIBLE_CHILD;
        let online = online_registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "search",
                json!({ "query": query }),
            )
            .await
            .expect("online search");
        let offline = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "search",
                json!({ "query": query }),
            )
            .await
            .expect("member search");
        assert_no_counter_fields(&offline, "member search");
        assert_eq!(hit_ids(&online), hit_ids(&offline), "hit ordering parity");
        assert!(hit_ids(&offline).contains(&two_caller::VISIBLE_CHILD.to_owned()));

        // A hidden query: nothing about the hidden record, and no total that
        // includes it.
        let hidden_query = "b-only";
        let online_hidden = online_registry
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "search",
                json!({ "query": hidden_query }),
            )
            .await
            .expect("online hidden search");
        let offline_hidden = member_registry
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "search",
                json!({ "query": hidden_query }),
            )
            .await
            .expect("member hidden search");
        assert_no_counter_fields(&offline_hidden, "member hidden search");
        assert!(!hit_ids(&online_hidden).contains(&two_caller::B_ONLY.to_owned()));
        assert!(!hit_ids(&offline_hidden).contains(&two_caller::B_ONLY.to_owned()));
        assert_eq!(
            online_hidden["total"], offline_hidden["total"],
            "total over E(m) must match"
        );
        assert!(
            !offline_hidden.to_string().contains(two_caller::B_ONLY),
            "no hidden id may appear in a member search response"
        );

        member_db.close().await;
    }

    /// C2c-2 differential over the §7.2 item 1 hidden-only-change world: search
    /// must be at parity for B on every shipped input, must say nothing about
    /// the hidden records, and must ship the online display reference rather
    /// than recompute a slice-local prefix (Q6c).
    #[tokio::test]
    async fn member_search_over_hidden_change_is_parity_and_hides_hidden() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::mcp::registry::ToolRegistry;
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{hidden_change, online_visible_ids, ACCT_B};
        use crate::schema::ROOT_RECORD_ID;

        let worlds = hidden_change::build().await;
        // Slice-specific visible rows (allowed after the world builds) give a
        // non-vacuous multi-hit ranking sample that is shipped to B.
        for (id, body) in [
            ("b2000003-0000-4000-8000-000000000001", "rankterm alpha"),
            ("b2000003-0000-4000-8000-000000000002", "rankterm beta"),
            (
                "02000003-0000-4000-8000-000000000003",
                "unrelated visible sibling",
            ),
        ] {
            crate::member_offline_fixtures::mk_doc(&worlds.b, id, ROOT_RECORD_ID, Some(body), None)
                .await;
            crate::member_offline_fixtures::grant(
                &worlds.b,
                id,
                vec![AllowEntry::members(Capability::View)],
            )
            .await;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) =
            admit_member_copy_of(&dir, &worlds.b, ACCT_B, "scope-ref-b").await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(lifecycle, "scope-ref-b".to_owned(), 1, Vec::new());

        let hit_ids = |value: &Value| -> Vec<String> {
            value["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .map(|hit| hit["id"].as_str().expect("hit id").to_owned())
                .collect()
        };
        let score = |value: &Value, id: &str| -> Option<f64> {
            value["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .find(|hit| hit["id"] == id)
                .and_then(|hit| hit["score"].as_f64())
        };

        // Ranking, ordering and scores are corpus-independent, so the shipped
        // index must agree with online for multiple hits.
        let online_rank = search_value(&online, &worlds.b, ACCT_B, "rankterm").await;
        let offline_rank = search_value(&offline, &member_db, ACCT_B, "rankterm").await;
        assert_no_counter_fields(&offline_rank, "member rank search");
        assert!(
            hit_ids(&offline_rank).len() >= 2,
            "ranking sample must be non-vacuous: {offline_rank}"
        );
        assert_eq!(
            hit_ids(&online_rank),
            hit_ids(&offline_rank),
            "ranking/ordering parity"
        );
        for id in hit_ids(&online_rank) {
            assert_eq!(
                score(&online_rank, &id),
                score(&offline_rank, &id),
                "score parity for {id}"
            );
        }

        // Every result field, including snippets and positive visible near
        // misses, must match the online answer over E(B).
        for field in [
            "hits",
            "total",
            "returned",
            "limit",
            "limit_reached",
            "thin",
            "guidance",
            "near_misses",
        ] {
            assert_eq!(
                online_rank[field], offline_rank[field],
                "search {field} parity"
            );
        }
        assert_eq!(offline_rank["thin"], json!(true));
        assert!(
            offline_rank["hits"].as_array().unwrap().iter().all(|hit| {
                hit["snippet"]
                    .as_str()
                    .is_some_and(|snippet| !snippet.is_empty())
            }),
            "snippet parity sample must be non-empty"
        );
        let siblings = offline_rank["near_misses"]["tree_siblings"]
            .as_array()
            .expect("siblings");
        assert!(
            siblings
                .iter()
                .any(|hit| hit["id"] == "02000003-0000-4000-8000-000000000003"),
            "visible near-miss sample must be served"
        );

        // A caller-selected cap must exercise the capped guidance branch,
        // rather than treating a one-hit cap as a thin result.
        let capped_args = json!({"query": "rankterm", "limit": 1});
        let online_capped = online
            .call(
                worlds.b.clone(),
                crate::mcp::registry::Caller::authenticated(ACCT_B),
                "search",
                capped_args.clone(),
            )
            .await
            .expect("online capped search");
        let offline_capped = offline
            .call(
                member_db.clone(),
                crate::mcp::registry::Caller::member_copy(ACCT_B),
                "search",
                capped_args,
            )
            .await
            .expect("offline capped search");
        for field in [
            "hits",
            "total",
            "returned",
            "limit",
            "limit_reached",
            "thin",
            "guidance",
            "near_misses",
        ] {
            assert_eq!(
                online_capped[field], offline_capped[field],
                "capped search {field} parity"
            );
        }
        assert_eq!(offline_capped["limit_reached"], json!(true));
        assert_eq!(offline_capped["thin"], json!(false));
        assert!(offline_capped["guidance"].is_string());
        assert!(offline_capped.get("near_misses").is_none());

        // Terms matching hidden names/bodies return nothing about them: no
        // hits, no totals, no near-miss candidates carrying a hidden id.
        for query in [
            hidden_change::HIDDEN_BODY_BASE,
            hidden_change::HIDDEN_BODY_EDITED,
            hidden_change::HIDDEN_BODY_NEW,
            hidden_change::HIDDEN_BODY_PREFIX,
            hidden_change::HIDDEN_BODY_NEWER,
        ] {
            let online_hidden = search_value(&online, &worlds.b, ACCT_B, query).await;
            let offline_hidden = search_value(&offline, &member_db, ACCT_B, query).await;
            assert_no_counter_fields(&offline_hidden, "member hidden search");
            assert_eq!(
                online_hidden["total"], offline_hidden["total"],
                "hidden total parity for {query:?}"
            );
            assert_eq!(
                offline_hidden["total"],
                json!(0),
                "hidden term must match nothing for B: {query:?}"
            );
            let text = offline_hidden.to_string();
            for id in hidden_change::hidden_from_b() {
                assert!(!text.contains(id), "hidden id {id} leaked for {query:?}");
            }
        }

        // Q6c: a hidden prefix sibling keeps VIS_H's online reference
        // ambiguous, so online withholds it. The member copy must withhold it
        // too, never recompute a shorter slice-local prefix.
        let online_ref =
            search_value(&online, &worlds.b, ACCT_B, hidden_change::VIS_BODY_BASE).await;
        let offline_ref =
            search_value(&offline, &member_db, ACCT_B, hidden_change::VIS_BODY_BASE).await;
        assert!(hit_ids(&online_ref).contains(&hidden_change::VIS_H.to_owned()));
        assert_eq!(hit_ids(&online_ref), hit_ids(&offline_ref));
        let reference = |value: &Value| -> Option<String> {
            value["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .find(|hit| hit["id"] == hidden_change::VIS_H)
                .and_then(|hit| hit["display_reference"].as_str().map(str::to_owned))
        };
        assert_eq!(
            reference(&online_ref),
            reference(&offline_ref),
            "Q6c display-reference parity"
        );
        assert!(
            reference(&offline_ref).is_none(),
            "a slice-local recompute would fabricate a short hidden-unique prefix"
        );

        // Independent oracle: hidden handles are outside E(B), the visible hit
        // is inside it.
        let oracle = online_visible_ids(&worlds.b, ACCT_B).await;
        assert!(oracle.contains(hidden_change::VIS_H));
        for id in hidden_change::hidden_from_b() {
            assert!(!oracle.contains(id), "hidden id {id} must be outside E(B)");
        }

        member_db.close().await;
    }

    /// Q6c on the *successor* path (`annotate_superseded_by_in_tx`): a visible
    /// record's online short reference is withheld because the hidden B_ONLY
    /// shares its prefix. The member copy must ship that withheld value, not
    /// recompute a shorter slice-local prefix.
    #[tokio::test]
    async fn member_search_successor_reference_uses_the_shipped_value() {
        use crate::mcp::registry::ToolRegistry;
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        // A searchable body on the visible predecessor; its successor
        // NEWER_HIDDEN is visible to A and named in `superseded_by`.
        crate::store::update_record(
            &world.db,
            two_caller::OLD_RECORD,
            json!({ "body": "successorterm" }),
        )
        .await
        .expect("body");

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());

        let online_hit = search_value(&online, &world.db, ACCT_A, "successorterm").await;
        let offline_hit = search_value(&offline, &member_db, ACCT_A, "successorterm").await;
        assert_no_counter_fields(&offline_hit, "member successor search");
        let superseded = |value: &Value| -> Value {
            value["hits"]
                .as_array()
                .expect("hits")
                .iter()
                .find(|hit| hit["id"] == two_caller::OLD_RECORD)
                .map(|hit| hit["superseded_by"].clone())
                .expect("OLD_RECORD hit")
        };
        assert_eq!(
            superseded(&online_hit),
            superseded(&offline_hit),
            "successor references must come from the shipped table"
        );
        assert!(
            superseded(&offline_hit)["items"][0]
                .get("display_reference")
                .is_none(),
            "the withheld online reference must stay absent offline"
        );

        member_db.close().await;
    }

    /// Rev 8 §2.3(a): scan serves the computable axes over the slice at parity
    /// and returns explicit markers for the two axes that need excluded
    /// history. Convergence covers the served axes only and declares them.
    #[tokio::test]
    async fn member_scan_serves_computable_axes_and_marks_provenance() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;
        use std::collections::{BTreeMap, BTreeSet};

        let world = two_caller::build().await;
        // A visible, searchable, linked record whose genesis event is authored
        // by A, so the online `authored_by` axis is non-vacuous and its sample
        // participates in online convergence. This is the axis rev 8 excludes
        // offline, so it is the case that gives the convergence test teeth.
        let scan_id = "0a1b2c3d-0000-4000-8000-0000000000bb";
        crate::store::create_record_as(
            &world.db,
            json!({
                "id": scan_id,
                "type": "Document",
                "kind": "note",
                "name": "scanmarker note",
                "home_id": ROOT_RECORD_ID,
                "body": "scanmarker alpha",
            }),
            Some(ACCT_A),
        )
        .await
        .expect("authored scan record");
        crate::member_offline_fixtures::grant(
            &world.db,
            scan_id,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        crate::store::add_link(
            &world.db,
            crate::events::LinkAddedPayload {
                id: None,
                source_id: scan_id.into(),
                target_id: two_caller::SHARED_CHILD.into(),
                relationship: "mentions".into(),
                note: None,
            },
        )
        .await
        .expect("link");

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());

        let args = json!({ "query": "scanmarker", "high_degree_min": 1 });
        let online_scan = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "scan",
                args.clone(),
            )
            .await
            .expect("online scan");
        let offline_scan = offline
            .call(
                member_db.clone(),
                Caller::authenticated(ACCT_A),
                "scan",
                args,
            )
            .await
            .expect("member scan");
        assert_no_counter_fields(&offline_scan, "member scan");

        // Markers for the excluded history axes, exactly the shared shape.
        assert_eq!(
            offline_scan["census"]["provenance"]["unavailable_offline"]["surface"],
            json!("scan.provenance")
        );
        assert_eq!(
            offline_scan["census"]["provenance"]["unavailable_offline"]["retry"],
            json!("when_online")
        );
        assert_eq!(
            offline_scan["axes"]["authored_by"]["unavailable_offline"]["surface"],
            json!("scan.authored_by")
        );
        assert_eq!(
            offline_scan["axes"]["authored_by"]["unavailable_offline"]["retry"],
            json!("when_online")
        );

        // Computable surfaces at parity.
        assert_eq!(offline_scan["corpus_size"], online_scan["corpus_size"]);
        for key in ["by_type", "by_kind", "by_lifecycle"] {
            assert_eq!(
                offline_scan["census"][key], online_scan["census"][key],
                "{key}"
            );
        }
        for key in ["lexical", "recent", "high_degree", "containers"] {
            assert_eq!(offline_scan["axes"][key], online_scan["axes"][key], "{key}");
        }
        // Every served axis is non-vacuous, so an absent/null-equals-absent/
        // null comparison cannot pass for parity.
        for key in ["lexical", "recent", "high_degree", "containers"] {
            assert!(
                offline_scan["axes"][key]["count"].as_i64().unwrap_or(0) > 0,
                "served axis {key} must have a non-zero pool: {}",
                offline_scan["axes"][key]
            );
            assert!(
                !offline_scan["axes"][key]["samples"]
                    .as_array()
                    .expect("samples")
                    .is_empty(),
                "served axis {key} must show a sample"
            );
        }
        assert!(
            offline_scan["axes"]["high_degree"]["count"]
                .as_i64()
                .unwrap_or(0)
                > 0
        );
        assert!(
            offline_scan["axes"]["containers"]["count"]
                .as_i64()
                .unwrap_or(0)
                > 0
        );

        // Convergence is derived independently from the ONLINE samples of the
        // served axes only — never through the production helper — and the
        // member convergence must match it exactly.
        let served_axes_without = |include_authored_by: bool| -> BTreeSet<(String, Vec<String>)> {
            let mut appearances: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
            for (name, facet) in online_scan["axes"].as_object().expect("online axes") {
                if !include_authored_by && name == "authored_by" {
                    continue;
                }
                let Some(samples) = facet.get("samples").and_then(Value::as_array) else {
                    continue;
                };
                for sample in samples {
                    if let Some(id) = sample.get("id").and_then(Value::as_str) {
                        appearances
                            .entry(id.to_owned())
                            .or_default()
                            .insert(name.clone());
                    }
                }
            }
            appearances
                .into_iter()
                .filter(|(_, axes)| axes.len() >= 2)
                .map(|(id, axes)| (id, axes.into_iter().collect()))
                .collect()
        };
        let expected_served = served_axes_without(false);
        let expected_all = served_axes_without(true);
        assert_ne!(
            expected_served, expected_all,
            "excluding authored_by MUST change the expected convergence, or the test is vacuous"
        );
        let actual: BTreeSet<(String, Vec<String>)> = offline_scan["convergence"]
            .as_array()
            .expect("convergence")
            .iter()
            .map(|record| {
                let mut axes: Vec<String> = record["axes"]
                    .as_array()
                    .expect("axes")
                    .iter()
                    .map(|axis| axis.as_str().expect("axis").to_owned())
                    .collect();
                // Axis iteration order is not part of parity. Keep the Vec
                // so duplicate axes still fail the exact comparison.
                axes.sort();
                (record["id"].as_str().expect("id").to_owned(), axes)
            })
            .collect();
        assert_eq!(
            actual, expected_served,
            "member convergence must equal the online served-axis-only convergence"
        );
        assert_ne!(
            actual, expected_all,
            "member convergence must not include the excluded authored_by axis"
        );

        // The basis declares the served axes and the exclusion explicitly.
        let basis = &offline_scan["convergence_basis"];
        assert_eq!(basis["kind"], json!("served_axes"));
        assert_eq!(basis["excluded_axes"], json!(["authored_by"]));
        let served: Vec<String> = basis["axes"]
            .as_array()
            .expect("axes")
            .iter()
            .map(|value| value.as_str().expect("axis name").to_owned())
            .collect();
        for key in ["lexical", "recent", "high_degree", "containers"] {
            assert!(
                served.contains(&key.to_owned()),
                "served axes must name {key}"
            );
        }
        assert!(!served.contains(&"authored_by".to_owned()));
        for record in offline_scan["convergence"].as_array().expect("convergence") {
            for axis in record["axes"].as_array().expect("axes") {
                assert!(
                    served.contains(&axis.as_str().expect("axis").to_owned()),
                    "convergence named an unserved axis: {axis}"
                );
            }
        }

        // No hidden identity anywhere in the member response.
        for hidden in two_caller::hidden_from_a() {
            assert!(
                !offline_scan.to_string().contains(hidden),
                "hidden {hidden} leaked"
            );
        }

        // Online is unchanged: real provenance buckets and an authored_by
        // facet, no markers anywhere.
        assert!(online_scan["census"]["provenance"]["buckets"].is_array());
        assert!(online_scan["axes"]["authored_by"]["samples"].is_array());
        assert!(!online_scan.to_string().contains("unavailable_offline"));

        member_db.close().await;
    }

    /// C2c-3 harness: the shared `two_caller` world plus slice-specific
    /// additions (a same-name collision pair and instruction bindings),
    /// then a producer-built, admitted member copy for A with both
    /// registries gated. Seeding happens before the copy is cut, so the
    /// producer fold — not the test — decides what ships.
    struct C3Harness {
        _dir: tempfile::TempDir,
        world_db: crate::db::Db,
        member_db: crate::db::Db,
        lifecycle: Arc<Mutex<MemberCopyLifecycle>>,
    }

    const COLLISION_A: &str = "f1000000-0000-4000-8000-000000000101";
    const COLLISION_B: &str = "f1000000-0000-4000-8000-000000000102";
    const COLLISION_NAME: &str = "collision-name";

    async fn c3_harness(seed_hidden_binding: bool) -> C3Harness {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use serde_json::json;

        let world = two_caller::build().await;
        // Same-name pair, both members-visible: the ambiguity case.
        for id in [COLLISION_A, COLLISION_B] {
            crate::store::create_record(
                &world.db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "note",
                    "name": COLLISION_NAME,
                    "home_id": two_caller::SHARED,
                }),
            )
            .await
            .expect("collision record");
            crate::member_offline_fixtures::grant(
                &world.db,
                id,
                vec![AllowEntry::members(Capability::View)],
            )
            .await;
        }
        crate::member_offline_fixtures::insert_instruction_binding(
            &world.db,
            two_caller::BINDING_VISIBLE_SOURCE,
            ACCT_A,
            two_caller::SHARED_CHILD,
            0,
        )
        .await;
        if seed_hidden_binding {
            crate::member_offline_fixtures::insert_instruction_binding(
                &world.db,
                two_caller::BINDING_HIDDEN_SOURCE,
                ACCT_A,
                two_caller::B_ONLY,
                1,
            )
            .await;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        C3Harness {
            _dir: dir,
            world_db: world.db,
            member_db,
            lifecycle,
        }
    }

    fn c3_registries(lifecycle: Arc<Mutex<MemberCopyLifecycle>>) -> (ToolRegistry, ToolRegistry) {
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut member = ToolRegistry::new();
        register_builtin_tools(&mut member).expect("builtins");
        register_surface_tools(&mut member).expect("surface");
        member.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());
        (online, member)
    }

    /// C2c-3 differential (§7.2 item 4): `resolve_many` over the admitted
    /// copy equals the online answer as the same member — per-item parity,
    /// hidden/deleted/nonexistent indistinguishable as `not_found`, counts
    /// over the slice, `not_held` 0. The hidden-source binding is NOT
    /// seeded here (it would make online `invalid` by design; see the
    /// visibility test).
    #[tokio::test]
    async fn member_resolve_many_is_parity_and_hides_hidden() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use serde_json::json;

        let harness = c3_harness(false).await;
        let (online, member) = c3_registries(harness.lifecycle.clone());

        let names = vec![
            two_caller::SHARED_CHILD.to_owned(),
            two_caller::VISIBLE_CHILD.to_owned(),
            two_caller::B_ONLY.to_owned(),
            "definitely-not-a-record".to_owned(),
            COLLISION_NAME.to_owned(),
            two_caller::SHARED_CHILD.to_owned(),
        ];
        let args = json!({ "names": names });
        let online_answer = online
            .call(
                harness.world_db.clone(),
                Caller::authenticated(ACCT_A),
                "resolve_many",
                args.clone(),
            )
            .await
            .expect("online resolve_many");
        let offline_answer = member
            .call(
                harness.member_db.clone(),
                Caller::member_copy(ACCT_A),
                "resolve_many",
                args,
            )
            .await
            .expect("member resolve_many");
        assert_no_counter_fields(&offline_answer, "member resolve_many");

        // Full parity on the batch shape.
        for key in [
            "results",
            "counts",
            "type",
            "kind",
            "include_archived",
            "match",
        ] {
            assert_eq!(
                online_answer[key], offline_answer[key],
                "resolve_many[{key}] parity"
            );
        }
        let statuses: Vec<&str> = offline_answer["results"]
            .as_array()
            .expect("results")
            .iter()
            .map(|item| item["status"].as_str().expect("status"))
            .collect();
        assert_eq!(
            statuses,
            vec![
                "resolved",
                "resolved",
                "not_found",
                "not_found",
                "ambiguous",
                "resolved"
            ],
            "hidden, absent, collision and duplicate inputs"
        );
        assert_eq!(
            offline_answer["counts"],
            json!({
                "resolved": 3, "not_found": 2, "ambiguous": 1, "not_held": 0,
            })
        );
        // The collision ships both visible candidates, nothing hidden.
        let collision = &offline_answer["results"][4];
        assert_eq!(collision["match_count"], json!(2));
        assert_eq!(collision["matches"].as_array().expect("matches").len(), 2);
        // No hidden identity in any matched candidate: the `not_found`
        // items echo the caller's own inputs (as online does), but no
        // `match` or `matches` entry may name a hidden record.
        let mut matched_ids = Vec::new();
        for item in offline_answer["results"].as_array().expect("results") {
            if let Some(resolved) = item.get("match") {
                matched_ids.push(resolved["id"].as_str().expect("match id").to_owned());
            }
            for candidate in item
                .get("matches")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                matched_ids.push(candidate["id"].as_str().expect("candidate id").to_owned());
            }
        }
        assert!(
            !matched_ids.contains(&two_caller::B_ONLY.to_owned()),
            "no hidden id may resolve in a member batch response"
        );
        // Online legs are unchanged: no markers, `not_held` stays 0.
        assert!(!online_answer.to_string().contains("unavailable_offline"));
        assert_eq!(online_answer["counts"]["not_held"], json!(0));

        harness.member_db.close().await;
        harness.world_db.close().await;
    }

    /// C2c-3 differential (§7.2 item 4): reduced member bootstrap matches
    /// the online answer as the same member on every computable part —
    /// footing, world scan, instruction entries — while run/claim/intent
    /// are explicit markers, never empty defaults. Only the visible
    /// binding is seeded here, so online stays `ready` (the hidden-source
    /// divergence is pinned in the visibility test).
    #[tokio::test]
    async fn member_bootstrap_is_reduced_with_markers_and_slice_parity() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use serde_json::json;

        let harness = c3_harness(false).await;
        let (online, member) = c3_registries(harness.lifecycle.clone());

        let online_bootstrap = online
            .call(
                harness.world_db.clone(),
                Caller::authenticated(ACCT_A),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("online bootstrap");
        let offline_bootstrap = member
            .call(
                harness.member_db.clone(),
                Caller::member_copy(ACCT_A),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("member bootstrap");
        assert_no_counter_fields(&offline_bootstrap, "member bootstrap");

        // Footing parity: the same person, workspace and root.
        assert_eq!(
            online_bootstrap["principal"]["person_record_id"],
            offline_bootstrap["principal"]["person_record_id"],
            "person footing parity"
        );
        assert_eq!(
            online_bootstrap["principal"]["person_record_id"],
            json!(two_caller::PERSON_A)
        );
        assert_eq!(
            online_bootstrap["workspace"]["records_visible"],
            offline_bootstrap["workspace"]["records_visible"],
            "slice count parity"
        );
        assert_eq!(
            online_bootstrap["roots"], offline_bootstrap["roots"],
            "roots parity"
        );

        // World-scan parity: the same recent and open-work ids.
        let ids = |value: &Value, pointer: &str| -> Vec<String> {
            value
                .pointer(pointer)
                .expect("pointer")
                .as_array()
                .expect("items")
                .iter()
                .map(|item| item["id"].as_str().expect("id").to_owned())
                .collect()
        };
        assert_eq!(
            ids(&online_bootstrap, "/current_world/recent_activity/items"),
            ids(&offline_bootstrap, "/current_world/recent_activity/items"),
            "recent parity"
        );
        assert_eq!(
            ids(&online_bootstrap, "/current_world/open_work/items"),
            ids(&offline_bootstrap, "/current_world/open_work/items"),
            "open-work parity"
        );
        assert!(
            !ids(&offline_bootstrap, "/current_world/recent_activity/items").is_empty(),
            "the world scan must be non-vacuous"
        );

        // Instruction parity on entries and status; the member stack names
        // its missing obligation layer instead of an empty diagnostic list.
        assert_eq!(online_bootstrap["instructions"]["status"], json!("ready"));
        assert_eq!(
            online_bootstrap["instructions"]["status"],
            offline_bootstrap["instructions"]["status"]
        );
        assert_eq!(
            online_bootstrap["instructions"]["entries"],
            offline_bootstrap["instructions"]["entries"],
            "instruction entries parity"
        );
        assert_eq!(
            offline_bootstrap["instructions"]["entries"]
                .as_array()
                .expect("entries")
                .len(),
            2,
            "the build-owned engine entry plus exactly the visible binding"
        );
        assert_eq!(
            offline_bootstrap["instructions"]["diagnostics"],
            json!([{
                "code": "obligation_layer_unavailable_offline",
                "message": "Onboarding-derived instruction sources are unavailable on a member copy; see /pending_obligations.",
            }]),
        );

        // Run/claim/intent are markers with the contract surfaces.
        for (key, surface) in [
            ("/intentful_sessions", "bootstrap.intent"),
            ("/pending_obligations", "bootstrap.claim"),
            ("/run", "bootstrap.run"),
        ] {
            let marker = offline_bootstrap.pointer(key).expect("marker");
            assert_eq!(
                marker,
                &json!({ "unavailable_offline": { "surface": surface, "retry": "when_online" } }),
                "{key} must be an explicit marker"
            );
        }
        // The session key stays functional but is explicitly nondurable:
        // minted without storage reads, never persisted.
        assert_eq!(
            offline_bootstrap["session"]["nondurable"],
            json!(true),
            "member run key must be marked nondurable"
        );
        assert!(
            !offline_bootstrap["session"]["run_key"]
                .as_str()
                .expect("run key")
                .is_empty(),
            "member bootstrap still issues a run key"
        );

        // Online legs are unchanged: no markers, real obligations array.
        assert!(!online_bootstrap.to_string().contains("unavailable_offline"));
        assert!(online_bootstrap["pending_obligations"].is_array());
        assert!(online_bootstrap["session"]["run_key"].is_string());

        harness.member_db.close().await;
        harness.world_db.close().await;
    }

    /// Instruction-binding visibility (§2.4 item 13, §3.2): a binding ships
    /// only when its source is in E(m). With the hidden-source binding
    /// seeded, online stays fail-closed (`invalid`, so the owner can repair
    /// the caller's own binding) while the member stack is `ready` with
    /// only the shipped entry — a stated contract divergence, never a leak:
    /// the hidden binding id appears nowhere in the member response.
    #[tokio::test]
    async fn member_bootstrap_withholds_hidden_source_bindings() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use serde_json::json;

        let harness = c3_harness(true).await;
        let (online, member) = c3_registries(harness.lifecycle.clone());

        let online_bootstrap = online
            .call(
                harness.world_db.clone(),
                Caller::authenticated(ACCT_A),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("online bootstrap");
        assert_eq!(
            online_bootstrap["instructions"]["status"],
            json!("invalid"),
            "online names the unreadable own-binding as invalid"
        );
        let offline_bootstrap = member
            .call(
                harness.member_db.clone(),
                Caller::member_copy(ACCT_A),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("member bootstrap");
        assert_no_counter_fields(&offline_bootstrap, "member bootstrap");
        assert_eq!(offline_bootstrap["instructions"]["status"], json!("ready"));
        let entries = offline_bootstrap["instructions"]["entries"]
            .as_array()
            .expect("entries");
        assert_eq!(
            entries.len(),
            2,
            "the engine entry plus only the visible binding ships"
        );
        assert_eq!(entries[0]["scope"], json!("engine"));
        assert_eq!(
            entries[1]["source"]["record_id"],
            json!(two_caller::SHARED_CHILD)
        );
        let offline_text = offline_bootstrap.to_string();
        assert!(
            !offline_text.contains(two_caller::BINDING_HIDDEN_SOURCE),
            "hidden binding id must not ship"
        );
        assert!(
            !offline_text.contains(two_caller::B_ONLY),
            "hidden source id must not ship outside authored text"
        );

        harness.member_db.close().await;
        harness.world_db.close().await;
    }

    /// Redacted-orphan regression (§3.3 rule 1): the producer nulls
    /// `home_id` when a visible child's parent is hidden, so B's admitted
    /// slice holds parentless rows besides the canonical root. Member
    /// bootstrap must validate the root by its known id — never by
    /// census — so source-online and offline bootstrap both succeed, the
    /// orphan is not counted as a root child, and the hidden parent leaks
    /// nowhere.
    #[tokio::test]
    async fn member_bootstrap_succeeds_with_redacted_orphan_slice() {
        use crate::member_offline_fixtures::{two_caller, ACCT_B};
        use serde_json::json;

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_B, SCOPE).await;
        // The orphan is real in the admitted slice: B sees the child
        // whose hidden parent was redacted.
        let orphan_home: Option<String> =
            sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
                .bind(two_caller::VISIBLE_CHILD)
                .fetch_one(member_db.write_pool())
                .await
                .expect("orphan row");
        assert_eq!(orphan_home, None, "hidden parent is redacted to NULL");
        let parentless_non_root: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM records WHERE home_id IS NULL AND id != ?")
                .bind(crate::schema::ROOT_RECORD_ID)
                .fetch_one(member_db.write_pool())
                .await
                .expect("orphan count");
        assert!(
            parentless_non_root >= 1,
            "the slice must hold a redacted orphan for this regression"
        );

        let (online, member) = c3_registries(lifecycle);
        let online_bootstrap = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("source online bootstrap succeeds");
        let offline_bootstrap = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_B),
                "bootstrap",
                json!({}),
            )
            .await
            .expect("member bootstrap succeeds with an orphan slice");
        assert_no_counter_fields(&offline_bootstrap, "member bootstrap");
        assert_eq!(
            offline_bootstrap["principal"]["person_record_id"],
            json!(two_caller::PERSON_B)
        );
        assert_eq!(
            online_bootstrap["roots"], offline_bootstrap["roots"],
            "the orphan is not counted as a root child"
        );
        assert!(
            !offline_bootstrap
                .to_string()
                .contains(two_caller::HIDDEN_PARENT),
            "hidden parent must leak nowhere in the member response"
        );

        member_db.close().await;
        world.db.close().await;
    }

    /// Copy-level gate (R6, §6.1): while the copy is locked, bootstrap and
    /// resolve_many refuse with the typed state before any surface logic
    /// runs — no handler, no storage, no id probe.
    #[test]
    fn member_bootstrap_and_resolve_many_refuse_while_locked() {
        use serde_json::json;

        let (_dir, lifecycle) = ready_lifecycle();
        lifecycle
            .lock()
            .expect("lock")
            .apply_reconnect(ReconnectAnswer::Locked)
            .expect("locked");
        let gate = MemberCopyGate::new(lifecycle, SCOPE.to_owned(), 1, Vec::new());
        for (kind, name, args) in [
            (Some(ToolKind::Bootstrap), "bootstrap", json!({})),
            (
                Some(ToolKind::ResolveMany),
                "resolve_many",
                json!({ "names": ["anything"] }),
            ),
        ] {
            let error = gate
                .admit(kind, name, &args)
                .expect_err("locked copy must refuse");
            assert!(
                matches!(&error, crate::error::Error::CopyLocked { .. }),
                "{name}: expected CopyLocked, got {error:?}"
            );
            assert_refusal_clean(&error);
        }
    }

    /// Over-shipment detector for the batch surface: a producer-built copy
    /// with a digest-fixed planted hidden row is admitted (admission proves
    /// closure, not eligibility), and the differential must catch the
    /// wrong slice — offline `resolved` where online-as-member says
    /// `not_found`.
    #[tokio::test]
    async fn overshipped_hidden_row_is_caught_by_resolve_many() {
        use crate::holding::ReplicaScope;
        use crate::mcp::registry::Caller;
        use crate::member_copy_admission::{admit_member_copy, ExpectedFooting};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use serde_json::json;
        use sha2::Digest as _;

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: staged.clone(),
        };
        let mut copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");

        // Plant B_ONLY (hidden from A), then fix the digest and byte
        // identity so admission accepts the oversized slice.
        {
            let connection = rusqlite::Connection::open(&staged).expect("sqlite");
            connection
                .execute_batch(&format!(
                    "INSERT INTO records (id, type, kind, name, body, persistence, created_at, updated_at, archived) \
                     VALUES ('{}','Document','note','{}','b-only note','enduring','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0);",
                    two_caller::B_ONLY, two_caller::B_ONLY,
                ))
                .expect("plant hidden row");
            let digest = crate::member_digest::content_digest(&connection).expect("digest");
            drop(connection);
            copy.content_digest = digest.clone();
            copy.manifest.content_digest = digest;
            let bytes = std::fs::read(&staged).expect("bytes");
            copy.manifest.bytes.size_bytes = bytes.len() as u64;
            copy.manifest.bytes.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        }

        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let scope_ref = match &copy.manifest.scope {
            ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            ReplicaScope::Everything => panic!("producer copy is a member scope"),
        };
        let expected = ExpectedFooting {
            origin_database_id: copy.manifest.origin_database_id.clone(),
            scope_ref,
            consumer: copy.manifest.consumer.clone(),
        };
        let admitted = admit_member_copy(
            &copy_root,
            &staged,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &expected,
            &mut lifecycle,
        )
        .expect("admission accepts the digest-fixed oversized slice");
        let member_db = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");

        let args = json!({ "names": [two_caller::B_ONLY] });
        let served = crate::mcp::tools::resolution::resolve_many(
            member_db.clone(),
            Caller::member_copy(ACCT_A),
            args.clone(),
        )
        .await
        .expect("member resolve_many");
        let online = crate::mcp::tools::resolution::resolve_many(
            world.db.clone(),
            Caller::authenticated(ACCT_A),
            args,
        )
        .await
        .expect("online resolve_many");
        assert_eq!(
            served["results"][0]["status"],
            json!("resolved"),
            "the over-shipped hidden row resolves (the defect)"
        );
        assert_eq!(online["results"][0]["status"], json!("not_found"));
        assert_ne!(
            online["results"], served["results"],
            "the differential must detect an over-shipped hidden row"
        );
        assert_no_counter_fields(&served, "overshipped response");

        member_db.close().await;
        world.db.close().await;
    }

    /// Regression for the counter-scrubber parity defect: authored body, name,
    /// summary, facet values and authored JSON keys that read like counter
    /// tokens (`rec:123`/`obs:456`, a `seq` key) must ship verbatim, exactly as
    /// online (§3.3 rule 4; §2.3 parity). The scrubber removes only known
    /// metadata positions, so this is a producer-built admitted-copy check.
    #[tokio::test]
    async fn member_serves_authored_counter_like_payload_verbatim() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::events::FacetSetPayload;
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;

        let world = two_caller::build().await;
        // A declared object facet so a facet value is parsed as JSON (authored
        // keys reach the response as object keys, not as an opaque string).
        crate::member_offline_fixtures::schema_row(
            &world.db,
            "authored-counter-schema",
            json!({"shapes": {"Document:authoredcounter": {"facets": {"payload": {"type": "object"}}}}}),
            None,
        )
        .await;
        let id = "0a1b2c3d-0000-4000-8000-0000000000cc";
        crate::store::create_record(
            &world.db,
            json!({
                "id": id,
                "type": "Document",
                "kind": "authoredcounter",
                "name": "rec:123",
                "home_id": ROOT_RECORD_ID,
                "body": "obs:456",
                "summary": "rec:7",
            }),
        )
        .await
        .expect("record");
        crate::member_offline_fixtures::grant(
            &world.db,
            id,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        for (key, value) in [
            ("plain", "obs:456".to_string()),
            (
                "payload",
                serde_json::to_string(&json!({"seq": 11, "my_seq": 22})).expect("payload json"),
            ),
        ] {
            crate::store::set_facet(
                &world.db,
                id,
                FacetSetPayload {
                    key: key.to_string(),
                    value: Some(value),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .expect("facet");
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());

        let online_record = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                json!({ "ids": [id] }),
            )
            .await
            .expect("online get_record");
        let offline_record = offline
            .call(
                member_db.clone(),
                Caller::authenticated(ACCT_A),
                "get_record",
                json!({ "ids": [id] }),
            )
            .await
            .expect("member get_record");
        assert_no_counter_fields(&offline_record, "member authored counter payload");

        let facet_value = |record: &Value, key: &str| -> Value {
            record["records"][0]["facets"]
                .as_array()
                .expect("facets")
                .iter()
                .find(|facet| facet["key"] == key)
                .map(|facet| facet["value"].clone())
                .unwrap_or_else(|| panic!("facet {key} missing: {record}"))
        };
        for (field, expected) in [
            ("name", json!("rec:123")),
            ("body", json!("obs:456")),
            ("summary", json!("rec:7")),
        ] {
            assert_eq!(
                online_record["records"][0][field], expected,
                "online {field} must be the authored text"
            );
            assert_eq!(
                offline_record["records"][0][field], expected,
                "member {field} must ship the authored text verbatim"
            );
        }
        assert_eq!(
            facet_value(&online_record, "plain"),
            json!("obs:456"),
            "online plain facet value"
        );
        assert_eq!(
            facet_value(&offline_record, "plain"),
            json!("obs:456"),
            "member plain facet value must ship verbatim"
        );
        assert_eq!(
            facet_value(&offline_record, "payload"),
            json!({"seq": 11, "my_seq": 22}),
            "authored JSON keys inside the facet value must survive"
        );

        // Real metadata is still omitted at its known positions.
        assert!(
            offline_record["records"][0].get("version").is_none(),
            "record version must still be omitted"
        );
        for facet in offline_record["records"][0]["facets"]
            .as_array()
            .expect("facets")
        {
            assert!(
                facet.get("version").is_none(),
                "facet version must still be omitted: {facet}"
            );
        }

        member_db.close().await;
    }

    /// C4a harness: producer copy of `source` for `account`, fully admitted
    /// (including the derived indexes) and opened read-only, with online and
    /// member registries wired. The member gate binds the admitted
    /// `generation_id` — a trusted admitted coordinate, never caller input —
    /// into the page basis through the production driver seam.
    async fn admit_query_copy(
        dir: &tempfile::TempDir,
        source: &crate::db::Db,
        account: &str,
        tag: &str,
    ) -> (crate::db::Db, ToolRegistry, ToolRegistry, String) {
        use crate::member_copy_admission::{admit_member_copy, ExpectedFooting};

        let staged = dir.path().join(format!("staged-{tag}.db"));
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: account.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: staged.clone(),
        };
        let copy = crate::member_copy_producer::build_member_copy(source, request)
            .await
            .expect("producer");
        let copy_root = dir.path().join(format!("copy-{tag}"));
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let scope_ref = match &copy.manifest.scope {
            crate::holding::ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            crate::holding::ReplicaScope::Everything => panic!("member scope"),
        };
        let expected = ExpectedFooting {
            origin_database_id: copy.manifest.origin_database_id.clone(),
            scope_ref,
            consumer: copy.manifest.consumer.clone(),
        };
        let admitted = admit_member_copy(
            &copy_root,
            &staged,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &expected,
            &mut lifecycle,
        )
        .expect("admission");
        let generation_id = admitted.generation_id.clone();
        let member = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");
        let mut online = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut online).expect("builtins");
        crate::mcp::register_surface_tools(&mut online).expect("surface");
        let mut member_registry = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut member_registry).expect("builtins");
        crate::mcp::register_surface_tools(&mut member_registry).expect("surface");
        member_registry.set_member_copy_gate(
            Arc::new(Mutex::new(lifecycle)),
            SCOPE.to_owned(),
            admitted.ordinal,
            admitted.schema_incomplete_for.clone(),
        );
        member_registry.set_member_copy_generation_id(generation_id.clone());
        (member, online, member_registry, generation_id)
    }

    /// Strip generation-bound/opaque and online-only coordinates so the
    /// remaining slice-derived fields compare for parity. Authored payload
    /// (names, bodies, summaries, facet values) is never touched here; the
    /// verbatim test below guards it separately.
    fn normalize_query_response(value: &mut Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        for key in [
            "as_of",
            "content_head_seq",
            "resolved_content_seq",
            "local_database_id",
            "observed_at",
            "coordination_observation",
            "page_basis_digest",
            "next_request",
            "standby_context",
        ] {
            object.remove(key);
        }
        let Some(records) = object.get_mut("records").and_then(Value::as_array_mut) else {
            return;
        };
        for record in records {
            let Some(item) = record.as_object_mut() else {
                continue;
            };
            for key in [
                "version",
                "custody_boundary",
                "communication_origin",
                "federation_provenance",
                "superseded_by",
                "interpretation",
            ] {
                item.remove(key);
            }
        }
    }

    /// C2c-5: a visible folder is served over the slice (visible members only),
    /// and a collection whose scoped schema row was withheld refuses only that
    /// collection (`schema_incomplete_for`), never the whole surface.
    #[tokio::test]
    async fn member_open_collection_serves_visible_folder_and_refuses_marked_collection() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A, ACCT_B};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");

        // A's generation is schema-complete: the gated row embeds a record
        // visible to A, so the visible folder `SHARED` serves its visible
        // members only.
        let (member_a, _online_a, registry_a, _gen_a) =
            admit_query_copy(&dir, &world.db, ACCT_A, "c5a").await;
        let opened = registry_a
            .call(
                member_a.clone(),
                Caller::member_copy(ACCT_A),
                "open_collection",
                json!({ "id": two_caller::SHARED }),
            )
            .await
            .expect("open_collection is served on a complete generation");
        assert_eq!(opened["status"], json!("opened"));
        assert_eq!(opened["collection"]["kind"], json!("folder"));
        let members: Vec<&str> = opened["input"]["records"]
            .as_array()
            .expect("records array")
            .iter()
            .filter_map(|record| record["id"].as_str())
            .collect();
        assert!(
            members.contains(&two_caller::SHARED_CHILD),
            "the visible child is a member: {members:?}"
        );
        assert!(
            !members.contains(&two_caller::HIDDEN_COLLECTION),
            "a hidden collection is never listed: {members:?}"
        );
        crate::member_offline_fixtures::assert_no_counter_fields(&opened, "open_collection");

        // B's generation withheld the `SHARED`-scoped schema row that embeds a
        // record B cannot see; `open_collection` for `SHARED` refuses typed and
        // the refusal carries no counter.
        let (member_b, _online_b, registry_b, _gen_b) =
            admit_query_copy(&dir, &world.db, ACCT_B, "c5b").await;
        let error = registry_b
            .call(
                member_b.clone(),
                Caller::member_copy(ACCT_B),
                "open_collection",
                json!({ "id": two_caller::SHARED }),
            )
            .await
            .expect_err("B must refuse the marked collection");
        assert!(
            matches!(&error, Error::UnavailableOffline { requirement, .. } if requirement == "schema_incomplete"),
            "{error:?}"
        );
        assert_refusal_clean(&error);
    }

    /// C2c-5: the four declared schema surfaces run as positive member fixtures
    /// on a complete producer/admitted copy, report their promised fields, and
    /// carry no counter metadata. `describe_schema` reports exactly the shipped
    /// catalog (no invented engine tables with empty columns).
    #[tokio::test]
    async fn member_schema_surfaces_serve_with_the_shipped_catalog_and_member_basis() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member, _online, registry, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "c5schema").await;
        let caller = Caller::member_copy(ACCT_A);

        let schema = registry
            .call(member.clone(), caller.clone(), "describe_schema", json!({}))
            .await
            .expect("describe_schema is served on a member copy");
        let reported: std::collections::BTreeSet<String> = schema["tables"]
            .as_array()
            .expect("tables array")
            .iter()
            .filter_map(|table| table["name"].as_str().map(str::to_owned))
            .collect();
        let shipped: std::collections::BTreeSet<String> =
            crate::schema::member_schema::shipped_tables()
                .into_iter()
                .map(str::to_owned)
                .collect();
        assert_eq!(
            reported, shipped,
            "describe_schema reports exactly the shipped member catalog"
        );
        assert!(!reported.contains("content_events"));
        assert!(!reported.contains("meta_events"));
        assert!(
            schema["tables"]
                .as_array()
                .unwrap()
                .iter()
                .all(|table| !table["columns"].as_array().unwrap().is_empty()),
            "no invented table is listed with empty columns"
        );
        assert_no_counter_fields(&schema, "member describe_schema");

        let preview = registry
            .call(
                member.clone(),
                caller.clone(),
                "preview_record_shape",
                json!({ "type": "Document", "kind": "note" }),
            )
            .await
            .expect("preview_record_shape is served on a member copy");
        assert_eq!(preview["advisory_only"], json!(true));
        assert_eq!(preview["zero_authoritative_writes"], json!(true));
        assert!(
            preview["advisory_basis"].get("event_heads").is_none(),
            "the member preview omits the excluded log event heads"
        );
        assert_eq!(
            preview["advisory_basis"]["schema_state_revision"],
            json!("member-read-v1:schema-basis")
        );
        assert!(preview["selection"]["effective_facet_shape"].is_object());
        assert_no_counter_fields(&preview, "member preview_record_shape");

        let facets = registry
            .call(
                member.clone(),
                caller.clone(),
                "resolve_facets",
                json!({ "record_id": two_caller::SHARED_CHILD }),
            )
            .await
            .expect("resolve_facets is served on a member copy");
        assert_eq!(facets["record_id"], json!(two_caller::SHARED_CHILD));
        assert!(facets["shape"].is_object());
        assert!(facets["pack_shape"].is_object());
        assert_no_counter_fields(&facets, "member resolve_facets");

        let suggestions = registry
            .call(
                member.clone(),
                caller.clone(),
                "suggest_facet_values",
                json!({ "record_id": two_caller::SHARED_CHILD, "facet_key": "note" }),
            )
            .await
            .expect("suggest_facet_values is served on a member copy");
        assert_eq!(suggestions["facet_key"], json!("note"));
        assert!(suggestions["suggestions"].is_array());
        assert_no_counter_fields(&suggestions, "member suggest_facet_values");
    }

    /// C2c-5 §2.5 differential: a visible record inside an excluded collection
    /// with scoped schema is interpreted differently online (which reads all
    /// `schema_config` rows) than offline (which can see no such row). The
    /// member copy carries no visible metadata to rule this out, so
    /// `open_collection` refuses rather than emit a partial interpretation.
    #[tokio::test]
    async fn member_open_collection_refuses_when_an_excluded_home_bears_scoped_schema() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::events::FacetSetPayload;
        use crate::member_offline_fixtures::{grant, link, schema_row, two_caller, ACCT_A, ACCT_B};
        use crate::schema::ROOT_RECORD_ID;

        const SELECTION: &str = "c5d10000-0000-4000-8000-000000000001";
        const HIDDEN_SCHEMA: &str = "c5d10000-0000-4000-8000-000000000002";

        // Build the same visible world twice; world 2 additionally anchors a
        // scoped schema row on the collection that contains VISIBLE_CHILD and
        // is excluded from B's copy.
        let mut worlds = Vec::new();
        for add_hidden_schema in [false, true] {
            let world = two_caller::build().await;
            crate::store::create_record(
                &world.db,
                json!({
                    "id": SELECTION,
                    "type": "Collection",
                    "kind": "selection",
                    "name": SELECTION,
                    "home_id": ROOT_RECORD_ID,
                }),
            )
            .await
            .unwrap();
            grant(
                &world.db,
                SELECTION,
                vec![AllowEntry::members(Capability::View)],
            )
            .await;
            link(
                &world.db,
                "c5d1-link",
                two_caller::VISIBLE_CHILD,
                SELECTION,
                "member_of",
            )
            .await;
            // A declared facet whose stored text is a number string: online
            // decodes it to an integer only when the hidden scoped row applies.
            crate::store::set_facet(
                &world.db,
                two_caller::VISIBLE_CHILD,
                FacetSetPayload {
                    key: "c5diff".into(),
                    value: Some("42".to_owned()),
                    vocab_ref: None,
                    as_of: None,
                    observation_only: false,
                },
            )
            .await
            .unwrap();
            if add_hidden_schema {
                schema_row(
                    &world.db,
                    HIDDEN_SCHEMA,
                    json!({"shapes": {"Document:note": {"facets": {"c5diff": {"type": "number"}}}}}),
                    Some(two_caller::HIDDEN_PARENT),
                )
                .await;
            }
            worlds.push(world);
        }

        // Demonstrated divergence: the excluded containing collection's scoped
        // schema changes the interpretation fetched for that home online.
        let rows_without = crate::query::cascade::schema_config_rows(&worlds[0].db, None)
            .await
            .unwrap();
        let rows_with = crate::query::cascade::schema_config_rows(&worlds[1].db, None)
            .await
            .unwrap();
        let shape_without = crate::query::cascade::facets_for_record_context(
            &rows_without,
            "Document",
            Some("note"),
            Some(two_caller::HIDDEN_PARENT),
        );
        let shape_with = crate::query::cascade::facets_for_record_context(
            &rows_with,
            "Document",
            Some("note"),
            Some(two_caller::HIDDEN_PARENT),
        );
        assert_ne!(
            shape_without, shape_with,
            "the excluded home's scoped schema changes the online interpretation"
        );
        assert!(shape_with.contains_key("c5diff"));

        // Offline refuses in both worlds: the copy cannot tell whether the
        // excluded home bears scoped schema.
        let dir = tempfile::tempdir().expect("tempdir");
        for (index, world) in worlds.iter().enumerate() {
            let (member, _online, registry, _generation) =
                admit_query_copy(&dir, &world.db, ACCT_B, &format!("c5diff{index}")).await;
            let error = registry
                .call(
                    member,
                    Caller::member_copy(ACCT_B),
                    "open_collection",
                    json!({ "id": SELECTION }),
                )
                .await
                .expect_err("open_collection must refuse an excluded containing collection");
            assert!(
                matches!(
                    &error,
                    Error::UnavailableOffline { requirement, .. }
                        if requirement == "schema_provenance_hidden"
                ),
                "{error:?}"
            );
            assert_refusal_clean(&error);
        }

        // The visible collection the same member can open stays usable.
        let (member_a, _online_a, registry_a, _generation_a) =
            admit_query_copy(&dir, &worlds[0].db, ACCT_A, "c5diffa").await;
        assert!(
            registry_a
                .call(
                    member_a,
                    Caller::member_copy(ACCT_A),
                    "open_collection",
                    json!({ "id": SELECTION }),
                )
                .await
                .is_ok(),
            "a collection without a nulled-home member is served"
        );
    }

    /// C2c-5: `native:root` is the one legitimately parentless record (NULL
    /// home), and no scoped schema can apply to a NULL home online, so a
    /// collection whose members include root is served at parity rather than
    /// over-refused. An unaffected collection still serves.
    #[tokio::test]
    async fn member_open_collection_serves_a_collection_containing_the_canonical_root() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{grant, link, two_caller, ACCT_B};
        use crate::schema::ROOT_RECORD_ID;

        const SELECTION: &str = "c5f10000-0000-4000-8000-000000000001";
        const FOLDER: &str = "c5f10000-0000-4000-8000-000000000002";
        const FOLDER_CHILD: &str = "c5f10000-0000-4000-8000-000000000003";

        let world = two_caller::build().await;
        crate::store::create_record(
            &world.db,
            json!({
                "id": SELECTION,
                "type": "Collection",
                "kind": "selection",
                "name": SELECTION,
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        grant(
            &world.db,
            SELECTION,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        link(
            &world.db,
            "c5f1-link",
            ROOT_RECORD_ID,
            SELECTION,
            "member_of",
        )
        .await;

        // A second, unaffected visible folder with a normal child.
        crate::store::create_record(
            &world.db,
            json!({
                "id": FOLDER,
                "type": "Collection",
                "kind": "folder",
                "name": FOLDER,
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        grant(
            &world.db,
            FOLDER,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        crate::store::create_record(
            &world.db,
            json!({
                "id": FOLDER_CHILD,
                "type": "Document",
                "kind": "note",
                "name": FOLDER_CHILD,
                "home_id": FOLDER,
            }),
        )
        .await
        .unwrap();
        grant(
            &world.db,
            FOLDER_CHILD,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;

        let dir = tempfile::tempdir().expect("tempdir");
        let (member, online, registry, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_B, "c5root").await;

        let member_opened = registry
            .call(
                member,
                Caller::member_copy(ACCT_B),
                "open_collection",
                json!({ "id": SELECTION }),
            )
            .await
            .expect("a collection containing native:root is served offline");
        assert_eq!(member_opened["status"], json!("opened"));

        let online_opened = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "open_collection",
                json!({ "id": SELECTION }),
            )
            .await
            .expect("online serves the same collection");

        let root_of = |opened: &Value| -> Value {
            opened["input"]["records"]
                .as_array()
                .expect("records array")
                .iter()
                .find(|record| record["id"] == json!(ROOT_RECORD_ID))
                .cloned()
                .expect("canonical root is a member")
        };
        let member_root = root_of(&member_opened);
        let online_root = root_of(&online_opened);
        assert_eq!(
            member_root["home_id"],
            Value::Null,
            "root's canonical home is NULL"
        );
        for field in ["id", "type", "kind", "name", "summary"] {
            assert_eq!(
                member_root[field], online_root[field],
                "promised field '{field}' is at online parity for root"
            );
        }
        assert_no_counter_fields(&member_opened, "member open_collection root");

        // An unaffected visible collection (no root, no nulled home) survives.
        let (member_other, _online_other, registry_other, _generation_other) =
            admit_query_copy(&dir, &world.db, ACCT_B, "c5root2").await;
        assert!(
            registry_other
                .call(
                    member_other,
                    Caller::member_copy(ACCT_B),
                    "open_collection",
                    json!({ "id": FOLDER }),
                )
                .await
                .is_ok(),
            "an unaffected collection is still served"
        );
    }

    /// C2c-5: renderers list visible artifact records only; a hidden artifact
    /// with a `renders` binding is neither listed nor counted.
    #[tokio::test]
    async fn member_open_collection_lists_only_visible_renderers() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{grant, link, two_caller, ACCT_A, ACCT_B};
        use crate::schema::ROOT_RECORD_ID;

        const FOLDER: &str = "c5e10000-0000-4000-8000-000000000001";
        const VISIBLE_ART: &str = "c5e10000-0000-4000-8000-000000000002";
        const HIDDEN_ART: &str = "c5e10000-0000-4000-8000-000000000003";

        let world = two_caller::build().await;
        crate::store::create_record(
            &world.db,
            json!({
                "id": FOLDER,
                "type": "Collection",
                "kind": "folder",
                "name": FOLDER,
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .unwrap();
        grant(
            &world.db,
            FOLDER,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        for (id, grants) in [
            (VISIBLE_ART, vec![AllowEntry::members(Capability::View)]),
            (
                HIDDEN_ART,
                vec![AllowEntry::account(ACCT_A, Capability::View)],
            ),
        ] {
            crate::store::create_record(
                &world.db,
                json!({
                    "id": id,
                    "type": "Document",
                    "kind": "artifact",
                    "name": id,
                    "home_id": ROOT_RECORD_ID,
                }),
            )
            .await
            .unwrap();
            grant(&world.db, id, grants).await;
            link(&world.db, &format!("c5e1-link-{id}"), id, FOLDER, "renders").await;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let (member, _online, registry, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_B, "c5render").await;
        let opened = registry
            .call(
                member,
                Caller::member_copy(ACCT_B),
                "open_collection",
                json!({ "id": FOLDER }),
            )
            .await
            .expect("open_collection is served");
        let renderers = opened["renderers"].as_array().expect("renderers array");
        let ids: Vec<&str> = renderers
            .iter()
            .filter_map(|renderer| renderer["id"].as_str())
            .collect();
        assert_eq!(
            ids,
            vec![VISIBLE_ART],
            "only the visible renderer is listed"
        );
        let serialized = serde_json::to_string(&opened).unwrap();
        assert!(
            !serialized.contains(HIDDEN_ART),
            "a hidden renderer's id never appears"
        );
        assert_no_counter_fields(&opened, "member open_collection renderers");
    }

    /// C2c-5 / C4b F2 carry: a real marked generation refuses a `schema_config`
    /// read through the registry, while an unrelated relation stays served.
    #[tokio::test]
    async fn member_query_sql_refuses_schema_config_in_a_marked_generation() {
        use crate::member_offline_fixtures::{two_caller, ACCT_B};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        // B's generation withholds the `SHARED`-scoped schema row (it embeds a
        // record B cannot see), so `schema_incomplete_for` is non-empty.
        let (member, _online, registry, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_B, "c5qsql").await;
        let caller = Caller::member_copy(ACCT_B);

        let error = registry
            .call(
                member.clone(),
                caller.clone(),
                "query_sql",
                json!({ "sql": "SELECT id FROM schema_config" }),
            )
            .await
            .expect_err("a schema_config read must refuse in a marked generation");
        assert!(
            matches!(
                &error,
                Error::UnavailableOffline { requirement, .. } if requirement == "schema_config"
            ),
            "{error:?}"
        );
        assert_refusal_clean(&error);

        let served = registry
            .call(
                member,
                caller,
                "query_sql",
                json!({ "sql": "SELECT id FROM records" }),
            )
            .await
            .expect("an unrelated relation is served");
        assert_no_counter_fields(&served, "member query_sql");
    }

    /// C4a: filter + ordered multipage parity over the admitted slice, with
    /// authored counter-like text preserved verbatim and metadata-only R5.
    #[tokio::test]
    async fn member_query_record_filter_pages_are_parity() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{grant, mk_doc, two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;

        let world = two_caller::build().await;
        for n in 0..8 {
            let id = format!("c4a10000-0000-4000-8000-{n:012}");
            mk_doc(&world.db, &id, ROOT_RECORD_ID, Some("paging seed"), None).await;
            grant(&world.db, &id, vec![AllowEntry::members(Capability::View)]).await;
        }
        let authored_id = "c4a10000-0000-4000-8000-000000000099";
        crate::store::create_record(
            &world.db,
            serde_json::json!({
                "id": authored_id,
                "type": "Document",
                "kind": "note",
                "name": "c4a rec:123 note",
                "body": "body obs:456 with seq 7",
                "home_id": ROOT_RECORD_ID,
            }),
        )
        .await
        .expect("authored seed");
        grant(
            &world.db,
            authored_id,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;

        let oracle = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_A).await;
        assert!(
            oracle.contains(authored_id),
            "authored seed must be in E(m)"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q1").await;
        let caller_online = Caller::authenticated(ACCT_A);
        let caller_member = Caller::member_copy(ACCT_A);
        let args = |limit: i64, offset: i64| {
            serde_json::json!({
                "steps": [{"step": "filter", "types": ["Document"]}],
                "limit": limit,
                "offset": offset,
            })
        };

        let mut seen_authored = false;
        for offset in [0, 3, 6] {
            let online_page = online
                .call(
                    world.db.clone(),
                    caller_online.clone(),
                    "query_record",
                    args(3, offset),
                )
                .await
                .expect("online page");
            let mut offline_page = member
                .call(
                    member_db.clone(),
                    caller_member.clone(),
                    "query_record",
                    args(3, offset),
                )
                .await
                .expect("offline page");
            assert_no_counter_fields(&offline_page, "member query page");
            assert!(
                online_page["total"].as_i64().unwrap_or(0) > 3,
                "fixture must span pages"
            );
            assert_eq!(online_page["total"], offline_page["total"], "total parity");
            assert_eq!(
                online_page["returned"], offline_page["returned"],
                "page size parity"
            );
            assert_eq!(
                online_page["has_more"], offline_page["has_more"],
                "has_more parity"
            );
            for hit in offline_page["records"].as_array().expect("records") {
                let id = hit["id"].as_str().expect("hit id");
                assert!(
                    oracle.contains(id),
                    "served {id} must be in the E(m) oracle"
                );
                assert!(
                    !hit.to_string().contains(two_caller::B_ONLY),
                    "no hidden id may appear in a member page"
                );
                if id == authored_id {
                    seen_authored = true;
                    assert_eq!(hit["name"], serde_json::json!("c4a rec:123 note"));
                    assert_eq!(hit["body"], serde_json::json!("body obs:456 with seq 7"));
                }
            }
            let mut online_norm = online_page.clone();
            normalize_query_response(&mut online_norm);
            normalize_query_response(&mut offline_page);
            assert_eq!(online_norm, offline_page, "page parity at offset {offset}");
        }
        assert!(seen_authored, "authored seed must surface on some page");
        assert!(
            !two_caller::visible_to_a()
                .iter()
                .any(|id| !oracle.contains(*id)),
            "oracle covers the world's visible list"
        );
        member_db.close().await;
    }

    /// C4a: count_by axes, scalar aggregates and facet filters over the
    /// slice, all nonzero with online parity.
    #[tokio::test]
    async fn member_query_record_counts_aggregates_facets_are_parity() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::events::FacetSetPayload;
        use crate::member_offline_fixtures::{grant, mk_doc, two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;
        use crate::store::set_facet;

        let world = two_caller::build().await;
        for (n, color, weight) in [
            (0, "red", "10"),
            (1, "blue", "20"),
            (2, "red", "30"),
            (3, "blue", "40"),
        ] {
            let id = format!("c4a20000-0000-4000-8000-{n:012}");
            mk_doc(&world.db, &id, ROOT_RECORD_ID, Some("facet seed"), None).await;
            grant(&world.db, &id, vec![AllowEntry::members(Capability::View)]).await;
            for (key, value) in [("c4a-color", color), ("c4a-weight", weight)] {
                set_facet(
                    &world.db,
                    &id,
                    FacetSetPayload {
                        key: key.into(),
                        value: Some(value.into()),
                        vocab_ref: None,
                        as_of: None,
                        observation_only: false,
                    },
                )
                .await
                .expect("facet seed");
            }
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q2").await;
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "type",
                serde_json::json!({"steps": [{"step": "filter"}], "count_by": "type"}),
            ),
            (
                "kind",
                serde_json::json!({"steps": [{"step": "filter"}], "count_by": "kind"}),
            ),
            (
                "facet",
                serde_json::json!({
                    "steps": [{"step": "filter"}],
                    "count_by": "facet",
                    "facet_key": "c4a-color",
                }),
            ),
            (
                "filter-facet",
                serde_json::json!({
                    "steps": [{"step": "filter", "facets": [{"key": "c4a-color", "eq": "red"}]}],
                }),
            ),
            (
                "count",
                serde_json::json!({
                    "steps": [{"step": "filter", "types": ["Document"]}],
                    "aggregate": {"op": "count"},
                }),
            ),
            (
                "sum",
                serde_json::json!({
                    "steps": [{"step": "filter", "types": ["Document"]}],
                    "aggregate": {"op": "sum", "facet_key": "c4a-weight"},
                }),
            ),
        ];
        for (label, arguments) in cases {
            let online_out = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_A),
                    "query_record",
                    arguments.clone(),
                )
                .await
                .expect("online counts");
            let mut offline_out = member
                .call(
                    member_db.clone(),
                    Caller::member_copy(ACCT_A),
                    "query_record",
                    arguments,
                )
                .await
                .expect("offline counts");
            assert_no_counter_fields(&offline_out, "member {label}");
            assert!(
                offline_out.to_string().contains("c4a-color")
                    || offline_out["total"].as_i64().unwrap_or(0) > 0
                    || offline_out["value"].is_number(),
                "{label} must be a nonzero slice fold"
            );
            normalize_query_response(&mut offline_out);
            let mut online_norm = online_out.clone();
            normalize_query_response(&mut online_norm);
            assert_eq!(online_norm, offline_out, "{label} parity");
        }
        // Facet buckets name the seeded values with exact counts.
        let buckets = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                serde_json::json!({
                    "steps": [{"step": "filter"}],
                    "count_by": "facet",
                    "facet_key": "c4a-color",
                }),
            )
            .await
            .expect("facet buckets");
        let red = buckets["buckets"]
            .as_array()
            .expect("buckets")
            .iter()
            .find(|bucket| bucket["key"] == serde_json::json!("red"))
            .expect("red bucket");
        assert_eq!(
            red["count"],
            serde_json::json!(2),
            "seeded facet count ships"
        );
        member_db.close().await;
    }

    /// C4a: hidden, deleted and never-existed ids are indistinguishable —
    /// empty on both legs, with identical (normalized) responses.
    #[tokio::test]
    async fn member_query_record_hidden_deleted_missing_are_indistinguishable() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{grant, mk_doc, two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;

        let world = two_caller::build().await;
        let deleted_id = "c4a30000-0000-4000-8000-000000000001";
        mk_doc(&world.db, deleted_id, ROOT_RECORD_ID, Some("doomed"), None).await;
        grant(
            &world.db,
            deleted_id,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        crate::store::delete_record(&world.db, deleted_id)
            .await
            .expect("delete");
        let missing_id = "c4a30000-0000-4000-8000-ffffffffffff";
        let oracle = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_A).await;
        assert!(!oracle.contains(two_caller::B_ONLY));
        assert!(!oracle.contains(deleted_id));
        assert!(!oracle.contains(missing_id));

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q3").await;
        for id in [two_caller::B_ONLY, deleted_id, missing_id] {
            let arguments = serde_json::json!({"steps": [{"step": "filter", "ids": [id]}]});
            let online_out = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_A),
                    "query_record",
                    arguments.clone(),
                )
                .await
                .expect("online absent");
            let mut offline_out = member
                .call(
                    member_db.clone(),
                    Caller::member_copy(ACCT_A),
                    "query_record",
                    arguments,
                )
                .await
                .expect("offline absent");
            assert_no_counter_fields(&offline_out, "member absent {id}");
            for output in [&online_out, &offline_out] {
                assert_eq!(
                    output["total"],
                    serde_json::json!(0),
                    "{id} must match nothing"
                );
                assert_eq!(
                    output["records"],
                    serde_json::json!([]),
                    "{id} must return no rows"
                );
            }
            let mut online_norm = online_out.clone();
            normalize_query_response(&mut online_norm);
            normalize_query_response(&mut offline_out);
            assert_eq!(online_norm, offline_out, "{id} indistinguishability");
        }
        member_db.close().await;
    }

    /// C4a: a true semantic Unit-bearer source seed through the public
    /// lower-level event seam (slice-specific rows, no shared-builder
    /// change): envelope `record.created` plus `unit.created.v1`, exactly
    /// as the freshness kernel consumes them. The unitized envelope leaves
    /// generic results on both legs; the bearer serves iff the oracle
    /// contains it; the member file ships no `semantic_units` table.
    #[tokio::test]
    async fn member_query_record_unit_bearer_is_excluded_on_both_legs() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{grant, mk_doc, two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;
        use crate::store::{append, AppendSpec};

        let world = two_caller::build().await;
        let bearer = "c4a40000-0000-4000-8000-000000000001";
        mk_doc(&world.db, bearer, ROOT_RECORD_ID, Some("borne body"), None).await;
        grant(
            &world.db,
            bearer,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        let envelope = "c4a40000-0000-4000-8000-000000000002";
        append(
            &world.db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Entity",
                    "kind": "semantic-unit",
                    "name": envelope,
                    "home_id": ROOT_RECORD_ID,
                }),
                actor: None,
            },
        )
        .await
        .expect("unit envelope");
        grant(
            &world.db,
            envelope,
            vec![AllowEntry::members(Capability::View)],
        )
        .await;
        append(
            &world.db,
            AppendSpec {
                record_id: envelope.to_string(),
                event_type: "unit.created.v1".into(),
                payload: serde_json::json!({
                    "semantic_contract_version": "native.freshness-kernel.v1",
                    "authority_bearer_record_id": bearer,
                    "label": "c4a-unit",
                }),
                actor: Some("test:c4a-unit".to_string()),
            },
        )
        .await
        .expect("unitize envelope");

        let oracle = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_A).await;
        assert!(!oracle.contains(envelope), "unit envelope must leave E(m)");

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q4").await;
        // Else-leg with teeth: selecting the envelope by id finds nothing
        // online either — exclusion, not absence from the slice. The bearer
        // serves exactly when the oracle contains it.
        let arguments = serde_json::json!({"steps": [{"step": "filter", "ids": [envelope]}]});
        let online_out = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "query_record",
                arguments,
            )
            .await
            .expect("online unit exclusion");
        assert_eq!(
            online_out["total"],
            serde_json::json!(0),
            "envelope excluded online"
        );
        let arguments = serde_json::json!({"steps": [{"step": "filter", "ids": [bearer]}]});
        let online_bearer = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "query_record",
                arguments,
            )
            .await
            .expect("online bearer");
        assert_eq!(
            online_bearer["total"],
            serde_json::json!(if oracle.contains(bearer) { 1 } else { 0 }),
            "bearer follows the oracle online"
        );
        // Full differential over everything: parity with both excluded.
        let arguments = serde_json::json!({"steps": [{"step": "filter"}], "limit": 500});
        let online_out = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "query_record",
                arguments.clone(),
            )
            .await
            .expect("online full");
        let mut offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                arguments,
            )
            .await
            .expect("offline full");
        assert_no_counter_fields(&offline_out, "member unit world");
        for hit in offline_out["records"].as_array().expect("records") {
            let id = hit["id"].as_str().expect("hit id");
            assert!(id != envelope, "unit envelope must not ship");
            assert!(
                oracle.contains(id),
                "served {id} must be in the E(m) oracle"
            );
        }
        let mut online_norm = online_out.clone();
        normalize_query_response(&mut online_norm);
        normalize_query_response(&mut offline_out);
        assert_eq!(online_norm, offline_out, "unit-world parity");
        let unit_table: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'semantic_units'",
        )
        .fetch_all(member_db.write_pool())
        .await
        .expect("member schema scan");
        assert!(unit_table.is_empty(), "member file ships no semantic_units");
        member_db.close().await;
    }

    /// C4a: the shipped display reference keeps its online length when a
    /// hidden record shares the prefix (Q6c); hidden parents null `home_id`
    /// with parity and hidden successors stay unnamed and uncounted.
    #[tokio::test]
    async fn member_query_record_references_and_hierarchy_are_parity() {
        use crate::member_offline_fixtures::{hidden_change, two_caller, ACCT_A, ACCT_B};

        // Display-ref collision: a hidden sibling shares VIS_H's prefix.
        let worlds = hidden_change::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &worlds.b, ACCT_B, "q5").await;
        let arguments =
            serde_json::json!({"steps": [{"step": "filter", "ids": [hidden_change::VIS_H]}]});
        let online_out = online
            .call(
                worlds.b.clone(),
                Caller::authenticated(ACCT_B),
                "query_record",
                arguments.clone(),
            )
            .await
            .expect("online ref");
        let offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_B),
                "query_record",
                arguments,
            )
            .await
            .expect("offline ref");
        assert_no_counter_fields(&offline_out, "member display ref");
        assert_eq!(
            online_out["records"][0]["display_reference"],
            offline_out["records"][0]["display_reference"],
            "shipped prefix keeps its online length"
        );
        member_db.close().await;

        // Hidden parent (B's view: HIDDEN_PARENT is A-only): home_id nulled
        // with identical visibility on both legs.
        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_B, "q6").await;
        let arguments = serde_json::json!({
            "steps": [{"step": "filter", "ids": [two_caller::VISIBLE_CHILD]}],
        });
        let online_out = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "query_record",
                arguments.clone(),
            )
            .await
            .expect("online child");
        let offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_B),
                "query_record",
                arguments,
            )
            .await
            .expect("offline child");
        for output in [&online_out, &offline_out] {
            assert_eq!(
                output["records"][0]["home_id"],
                serde_json::json!(null),
                "hidden parent nulls home_id"
            );
            assert_eq!(
                output["records"][0]["containment_path_visible"],
                serde_json::json!(false),
                "hidden parent breaks the visible path"
            );
        }

        // Hidden successor (B's view: NEWER_HIDDEN is A-only): only visible
        // successors are named or counted.
        let oracle = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_B).await;
        let arguments = serde_json::json!({
            "steps": [{"step": "filter", "ids": [two_caller::OLD_RECORD]}],
        });
        let online_out = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "query_record",
                arguments.clone(),
            )
            .await
            .expect("online succession");
        let offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_B),
                "query_record",
                arguments,
            )
            .await
            .expect("offline succession");
        // R1 interim divergence, documented: the successor link's hidden
        // endpoint never ships, so the slice has no visible successors and
        // the member row carries no succession section; online still counts
        // the hidden successor until e5f171c. Nothing hidden is named either
        // way, and the visible successor sets agree (both empty).
        assert!(
            offline_out["records"][0].get("superseded_by").is_none(),
            "no visible successors means no succession section offline"
        );
        let online_visible_items: Vec<&serde_json::Value> = online_out["records"][0]
            ["superseded_by"]["items"]
            .as_array()
            .expect("online items")
            .iter()
            .filter(|item| item["id"].as_str().is_some_and(|sid| oracle.contains(sid)))
            .collect();
        assert!(
            online_visible_items.is_empty(),
            "no successor is visible in the oracle"
        );
        assert!(
            online_out["records"][0]["superseded_by"]["total_count"]
                .as_i64()
                .unwrap_or(0)
                >= 1,
            "online still counts the hidden successor (pre-e5f171c)"
        );
        assert!(
            !offline_out.to_string().contains(two_caller::NEWER_HIDDEN),
            "hidden successor id never ships"
        );
        member_db.close().await;

        // Message markers (A's view: MSG_A is A-only): excluded Message
        // sections are explicit markers, never silent absences.
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, _online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q6msg").await;
        let offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                serde_json::json!({"steps": [{"step": "filter", "ids": [two_caller::MSG_A]}]}),
            )
            .await
            .expect("offline message");
        assert_no_counter_fields(&offline_out, "member message row");
        for key in [
            "communication_origin",
            "federation_provenance",
            "custody_boundary",
        ] {
            assert!(
                offline_out["records"][0][key]["unavailable_offline"].is_object(),
                "message {key} must be a marker"
            );
        }
        member_db.close().await;
    }

    /// C4a: `as_of`, `activity` and `include_coordination` refuse with typed
    /// `unavailable_offline` before any slice read.
    #[tokio::test]
    async fn member_query_record_gated_arguments_refuse() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, _online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q7").await;
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "as_of",
                serde_json::json!({"steps": [{"step": "filter"}], "as_of": {"content_seq": 1}}),
            ),
            (
                "activity",
                serde_json::json!({
                    "steps": [{"step": "filter"}],
                    "activity": {"limit": 5, "through_local_seq": 1},
                }),
            ),
            (
                "include_coordination",
                serde_json::json!({"steps": [{"step": "filter"}], "include_coordination": true}),
            ),
        ];
        for (requirement, arguments) in cases {
            let error = member
                .call(
                    member_db.clone(),
                    Caller::member_copy(ACCT_A),
                    "query_record",
                    arguments,
                )
                .await
                .expect_err("gated argument must refuse");
            match &error {
                crate::error::Error::UnavailableOffline {
                    surface,
                    requirement: got,
                } => {
                    assert_eq!(surface, "query_record");
                    assert_eq!(got, requirement, "refusal names the gated argument");
                }
                other => panic!("{requirement} must be unavailable_offline, got {other:?}"),
            }
            assert_refusal_clean(&error);
        }
        member_db.close().await;
    }

    /// C4a: `include_interpretation` serves the supported rows and counts
    /// with the declared marker on the `interpretation` section — never a
    /// whole-query refusal.
    #[tokio::test]
    async fn member_query_record_interpretation_marks_without_refusing() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q7b").await;
        let arguments = serde_json::json!({
            "steps": [{"step": "filter", "types": ["Document"]}],
            "limit": 2,
            "include_interpretation": true,
        });
        let online_out = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "query_record",
                arguments.clone(),
            )
            .await
            .expect("online interpretation");
        let offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                arguments,
            )
            .await
            .expect("offline interpretation serves");
        assert_no_counter_fields(&offline_out, "member interpretation");
        let rows = offline_out["records"].as_array().expect("rows");
        assert!(!rows.is_empty(), "interpretation still serves rows");
        assert!(
            offline_out["total"].as_i64().unwrap_or(0) > 0,
            "interpretation still serves counts"
        );
        for row in rows {
            assert!(
                row["interpretation"]["unavailable_offline"].is_object(),
                "each row marks its interpretation section"
            );
        }
        let mut online_norm = online_out.clone();
        normalize_query_response(&mut online_norm);
        let mut offline_norm = offline_out.clone();
        normalize_query_response(&mut offline_norm);
        assert_eq!(
            online_norm, offline_norm,
            "interpretation parity outside the marker"
        );
        // The dispatched continuation retains the request, so page 2 keeps
        // the same counts with the marker on every row.
        assert_eq!(
            offline_out["has_more"],
            serde_json::json!(true),
            "fixture must page"
        );
        let next = offline_out["next_request"].clone();
        assert_eq!(
            next.get("include_interpretation"),
            Some(&serde_json::json!(true)),
            "continuation retains the interpretation request"
        );
        let second = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                next,
            )
            .await
            .expect("continued interpretation page");
        assert_no_counter_fields(&second, "continued interpretation");
        assert_eq!(
            second["total"], offline_out["total"],
            "continued counts agree"
        );
        assert_eq!(
            second["offset"],
            serde_json::json!(2),
            "continued offset advances"
        );
        for row in second["records"].as_array().expect("continued rows") {
            assert!(
                row["interpretation"]["unavailable_offline"].is_object(),
                "continued rows keep the marker"
            );
        }
        member_db.close().await;
    }

    /// C4a: the page basis binds the admitted generation. A continuation
    /// minted under one generation succeeds under it and refuses under the
    /// next — even when the visible id set is unchanged (only authored
    /// content moved).
    #[tokio::test]
    async fn member_query_record_continuation_refuses_across_generations() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::member_offline_fixtures::{grant, mk_doc, two_caller, ACCT_A};
        use crate::schema::ROOT_RECORD_ID;

        let world = two_caller::build().await;
        for n in 0..4 {
            let id = format!("c4a80000-0000-4000-8000-{n:012}");
            mk_doc(&world.db, &id, ROOT_RECORD_ID, Some("paged seed"), None).await;
            grant(&world.db, &id, vec![AllowEntry::members(Capability::View)]).await;
        }
        let page = |limit: i64, offset: i64, basis: Option<String>| {
            let mut arguments = serde_json::json!({
                "steps": [{"step": "filter", "types": ["Document"]}],
                "limit": limit,
                "offset": offset,
            });
            if let Some(basis) = basis {
                arguments["if_page_basis_digest"] = serde_json::json!(basis);
            }
            arguments
        };

        let dir = tempfile::tempdir().expect("tempdir");
        let (member_a, _online, member_registry_a, generation_a) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q8a").await;
        let oracle_a = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_A).await;
        let first = member_registry_a
            .call(
                member_a.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                page(2, 0, None),
            )
            .await
            .expect("first page");
        assert_eq!(
            first["has_more"],
            serde_json::json!(true),
            "fixture must page"
        );
        let basis = first["page_basis_digest"]
            .as_str()
            .expect("opaque basis")
            .to_owned();
        assert!(basis.starts_with("sha256:"), "basis stays opaque");
        // The returned continuation retains the query and dispatches
        // unchanged through exhaustion, matching the online slice oracle.
        let mut next = first["next_request"].clone();
        assert!(next.is_object(), "continuation retains the query arguments");
        assert!(next.get("steps").is_some(), "continuation keeps its steps");
        let mut walked = first["records"].as_array().expect("rows").len();
        while next.is_object() {
            let page_out = member_registry_a
                .call(
                    member_a.clone(),
                    Caller::member_copy(ACCT_A),
                    "query_record",
                    next,
                )
                .await
                .expect("continuation dispatches unchanged");
            assert_no_counter_fields(&page_out, "continued page");
            for hit in page_out["records"].as_array().expect("rows") {
                let id = hit["id"].as_str().expect("hit id");
                assert!(
                    oracle_a.contains(id),
                    "continued {id} must be in the oracle"
                );
            }
            walked += page_out["records"].as_array().expect("rows").len();
            next = page_out["next_request"].clone();
        }
        assert_eq!(
            walked as i64,
            first["total"].as_i64().expect("total"),
            "continuation exhausts the slice"
        );
        // Same-generation manual continuation also succeeds.
        let second = member_registry_a
            .call(
                member_a.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                page(2, 2, Some(basis.clone())),
            )
            .await
            .expect("same-generation continuation");
        assert_eq!(second["records"].as_array().expect("rows").len(), 2);

        // New generation with the same visible ids (only a body edited).
        crate::store::update_record(
            &world.db,
            "c4a80000-0000-4000-8000-000000000000",
            serde_json::json!({"body": "edited body, same ids"}),
        )
        .await
        .expect("content edit");
        let (member_b, _online_b, member_registry_b, generation_b) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q8b").await;
        assert_ne!(
            generation_a, generation_b,
            "content edit mints a new generation"
        );
        let stale = member_registry_b
            .call(
                member_b.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                page(2, 2, Some(basis)),
            )
            .await
            .expect_err("stale basis must refuse");
        assert!(
            stale.to_string().contains("page basis changed"),
            "refusal names the stale basis: {stale:?}"
        );
        assert_refusal_clean(&stale);
        // A fresh first page under the new generation works.
        let fresh = member_registry_b
            .call(
                member_b.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                page(2, 0, None),
            )
            .await
            .expect("fresh page");
        assert_eq!(fresh["returned"], serde_json::json!(2));
        member_a.close().await;
        member_b.close().await;
    }

    /// C4a: the differential catches an overshipped slice — a hidden row
    /// planted pre-admission (with the digest fixed so admission accepts
    /// the oversized slice by design) is served offline while the oracle
    /// excludes it, so the harness reports the wrong slice.
    #[tokio::test]
    async fn member_query_record_overshipment_is_caught_by_the_differential() {
        use crate::member_copy_admission::{admit_member_copy, ExpectedFooting};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use sha2::Digest as _;

        let world = two_caller::build().await;
        let oracle = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_A).await;
        assert!(!oracle.contains(two_caller::B_ONLY));

        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged-q9.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: staged.clone(),
        };
        let mut copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        // Plant the hidden row, then fix the content digest and byte
        // identity so admission accepts the oversized slice by design.
        {
            let connection = rusqlite::Connection::open(&staged).expect("sqlite");
            connection
                .execute_batch(&format!(
                    "INSERT INTO records (id, type, kind, name, body, persistence, created_at, updated_at, archived) \
                     VALUES ('{}','Document','note','{}','b-only note','enduring','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0);",
                    two_caller::B_ONLY,
                    two_caller::B_ONLY,
                ))
                .expect("plant hidden row");
            let digest = crate::member_digest::content_digest(&connection).expect("digest");
            drop(connection);
            copy.content_digest = digest.clone();
            copy.manifest.content_digest = digest;
            let bytes = std::fs::read(&staged).expect("bytes");
            copy.manifest.bytes.size_bytes = bytes.len() as u64;
            copy.manifest.bytes.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        }
        let copy_root = dir.path().join("copy-q9");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let scope_ref = match &copy.manifest.scope {
            crate::holding::ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            crate::holding::ReplicaScope::Everything => panic!("member scope"),
        };
        let expected = ExpectedFooting {
            origin_database_id: copy.manifest.origin_database_id.clone(),
            scope_ref,
            consumer: copy.manifest.consumer.clone(),
        };
        let admitted = admit_member_copy(
            &copy_root,
            &staged,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &expected,
            &mut lifecycle,
        )
        .expect("admission accepts the digest-fixed slice");
        let member_db = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");
        let mut online = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut online).expect("builtins");
        crate::mcp::register_surface_tools(&mut online).expect("surface");
        let mut member = ToolRegistry::new();
        crate::mcp::register_builtin_tools(&mut member).expect("builtins");
        crate::mcp::register_surface_tools(&mut member).expect("surface");
        member.set_member_copy_gate(
            Arc::new(Mutex::new(lifecycle)),
            SCOPE.to_owned(),
            admitted.ordinal,
            admitted.schema_incomplete_for.clone(),
        );
        member.set_member_copy_generation_id(admitted.generation_id.clone());

        let arguments =
            serde_json::json!({"steps": [{"step": "filter", "ids": [two_caller::B_ONLY]}]});
        let online_out = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "query_record",
                arguments.clone(),
            )
            .await
            .expect("online hides planted row");
        let offline_out = member
            .call(
                member_db.clone(),
                Caller::member_copy(ACCT_A),
                "query_record",
                arguments,
            )
            .await
            .expect("offline serves planted row");
        assert_eq!(online_out["total"], serde_json::json!(0));
        assert_eq!(
            offline_out["total"],
            serde_json::json!(1),
            "planted hidden row is served offline"
        );
        assert!(
            !oracle.contains(
                offline_out["records"][0]["id"]
                    .as_str()
                    .expect("planted id")
            ),
            "the differential maps the served row outside the oracle: wrong slice"
        );
        member_db.close().await;
    }

    /// C4a: link/children/parents traversals run over the slice with online
    /// parity — producer ships only E(m)-internal links, so neighbours agree.
    #[tokio::test]
    async fn member_query_record_traversals_are_parity() {
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, online, member, _generation) =
            admit_query_copy(&dir, &world.db, ACCT_A, "q10").await;
        let oracle = crate::member_offline_fixtures::online_visible_ids(&world.db, ACCT_A).await;
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "children",
                serde_json::json!({
                    "steps": [
                        {"step": "filter", "ids": [two_caller::SHARED]},
                        {"step": "traverse", "target": "children"},
                    ],
                }),
            ),
            (
                "parents",
                serde_json::json!({
                    "steps": [
                        {"step": "filter", "ids": [two_caller::SHARED_CHILD]},
                        {"step": "traverse", "target": "parents"},
                    ],
                }),
            ),
            (
                "links",
                serde_json::json!({
                    "steps": [
                        {"step": "filter", "ids": [two_caller::SHARED_CHILD]},
                        {"step": "traverse", "target": "links"},
                    ],
                }),
            ),
        ];
        for (label, arguments) in cases {
            let online_out = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_A),
                    "query_record",
                    arguments.clone(),
                )
                .await
                .expect("online traversal");
            let mut offline_out = member
                .call(
                    member_db.clone(),
                    Caller::member_copy(ACCT_A),
                    "query_record",
                    arguments,
                )
                .await
                .expect("offline traversal");
            assert_no_counter_fields(&offline_out, "member {label}");
            for hit in offline_out["records"].as_array().expect("records") {
                let id = hit["id"].as_str().expect("hit id");
                assert!(oracle.contains(id), "neighbour {id} must be in the oracle");
            }
            let mut online_norm = online_out.clone();
            normalize_query_response(&mut online_norm);
            normalize_query_response(&mut offline_out);
            assert_eq!(online_norm, offline_out, "{label} parity");
        }
        member_db.close().await;
    }

    /// One `query_sql` call through a registry, like `search_value` above.
    /// Dispatch derives member handling from the `Db` open mode, so an
    /// ordinary authenticated caller exercises the production member path
    /// (gate admit, member slice execution, envelope scrub) end to end.
    async fn query_sql_value(
        registry: &crate::mcp::registry::ToolRegistry,
        db: &crate::db::Db,
        account: &str,
        sql: &str,
    ) -> Value {
        registry
            .call(
                db.clone(),
                crate::mcp::registry::Caller::authenticated(account),
                "query_sql",
                json!({ "sql": sql }),
            )
            .await
            .expect("query_sql")
    }

    /// Rev 8 §2.3(a) `query_sql`: rows at parity over the slice for the
    /// served governed relations, compiled catalog identical for every
    /// caller, envelope omits only `as_of_seq`, authored aliases and cells
    /// (`SELECT 1 AS seq`, `rec:123`/`obs:456`) verbatim, and hidden,
    /// deleted and missing records indistinguishable (zero rows either way).
    /// Producer-built admitted copy with the independent `online_visible_ids`
    /// oracle; online is queried as the same member.
    #[tokio::test]
    async fn member_query_sql_parity_catalog_and_literals() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());

        // Every served relation at full projection with deterministic order.
        // `records` currency (`is_current`/`successor_count`) is compared
        // separately below: hidden successors are never counted offline (the
        // R1 carve-out shared with `get_record`'s `superseded_by`). `blobs`
        // `external_ref` is compared separately too: the §2.4 item 11a
        // exact-id gate withholds values naming hidden records (NULL
        // offline), never the row.
        for sql in [
            "SELECT * FROM links ORDER BY id",
            "SELECT * FROM facet_values ORDER BY record_id, key, id",
            "SELECT * FROM facet_times ORDER BY record_id, key",
            "SELECT * FROM bindings ORDER BY record_id, system, identifier",
            "SELECT * FROM vocabularies ORDER BY id",
            "SELECT * FROM vocabulary_values ORDER BY vocabulary_id, value",
            "SELECT * FROM schema_config ORDER BY id",
        ] {
            let online_result = query_sql_value(&online, &world.db, ACCT_A, sql).await;
            let offline_result = query_sql_value(&offline, &member_db, ACCT_A, sql).await;
            assert_eq!(
                offline_result["columns"], online_result["columns"],
                "columns must match for {sql}"
            );
            assert_eq!(
                offline_result["rows"], online_result["rows"],
                "rows must match for {sql}"
            );
            assert_no_counter_fields(&offline_result, "member query_sql");
            assert!(
                offline_result.get("as_of_seq").is_none(),
                "member envelope must omit as_of_seq for {sql}"
            );
            assert!(
                online_result.get("as_of_seq").is_some(),
                "online control must carry as_of_seq for {sql}"
            );
        }

        // Blobs: rows at parity with the gated `external_ref` withheld
        // offline (NULL) where it names a hidden record; the row stays.
        {
            let sql = "SELECT * FROM blobs ORDER BY id";
            let online_result = query_sql_value(&online, &world.db, ACCT_A, sql).await;
            let offline_result = query_sql_value(&offline, &member_db, ACCT_A, sql).await;
            assert_eq!(
                offline_result["columns"], online_result["columns"],
                "blobs columns must match"
            );
            let strip = |rows: &Value| {
                rows.as_array()
                    .expect("rows")
                    .iter()
                    .map(|row| {
                        let mut row = row.clone();
                        row.as_object_mut().expect("row").remove("external_ref");
                        row
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                strip(&offline_result["rows"]),
                strip(&online_result["rows"]),
                "blobs rows must match outside the gated value"
            );
            let gated = |rows: &Value| {
                rows.as_array()
                    .expect("rows")
                    .iter()
                    .find(|row| row["storage_tier"] == "external")
                    .map(|row| row["external_ref"].clone())
                    .expect("external row present")
            };
            assert!(
                gated(&online_result["rows"]).is_string(),
                "online carries the external_ref value"
            );
            assert_eq!(
                gated(&offline_result["rows"]),
                Value::Null,
                "offline withholds the hidden-id-bearing value, never the row"
            );
            assert_no_counter_fields(&offline_result, "member query_sql blobs");
            assert!(offline_result.get("as_of_seq").is_none());
        }

        // Records: every column at parity except the currency pair, which
        // counts visible successors only. OLD_RECORD has a hidden successor
        // (NEWER_HIDDEN): online counts 1 with `is_current` NULL, offline
        // counts 0 with `is_current` 1 — and that divergence is required, so
        // a hidden count never ships.
        {
            let sql = "SELECT * FROM records ORDER BY id";
            let online_result = query_sql_value(&online, &world.db, ACCT_A, sql).await;
            let offline_result = query_sql_value(&offline, &member_db, ACCT_A, sql).await;
            assert_eq!(
                offline_result["columns"], online_result["columns"],
                "records columns must match"
            );
            let strip = |rows: &Value| {
                rows.as_array()
                    .expect("rows")
                    .iter()
                    .map(|row| {
                        let mut row = row.clone();
                        row.as_object_mut().expect("row").remove("is_current");
                        row.as_object_mut().expect("row").remove("successor_count");
                        row
                    })
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                strip(&offline_result["rows"]),
                strip(&online_result["rows"]),
                "records rows must match outside currency"
            );
            let currency = |rows: &Value, id: &str| {
                rows.as_array()
                    .expect("rows")
                    .iter()
                    .find(|row| row["id"] == id)
                    .map(|row| (row["is_current"].clone(), row["successor_count"].clone()))
                    .expect("row present")
            };
            // NEWER_HIDDEN is visible to A, so OLD_RECORD currency is at
            // parity here; the hidden-successor carve-out is pinned below
            // with B's copy (NEWER_HIDDEN is hidden from B).
            assert_eq!(
                currency(&offline_result["rows"], two_caller::OLD_RECORD),
                currency(&online_result["rows"], two_caller::OLD_RECORD),
                "currency at parity where the successor is visible"
            );
            assert_eq!(
                currency(&offline_result["rows"], two_caller::SHARED_CHILD),
                currency(&online_result["rows"], two_caller::SHARED_CHILD),
                "currency matches where no successor exists"
            );
            assert_no_counter_fields(&offline_result, "member query_sql records");
            assert!(offline_result.get("as_of_seq").is_none());
        }

        // R1 carve-out with teeth: B sees OLD_RECORD but not its successor
        // NEWER_HIDDEN. Online counts 1 with `is_current` NULL (a hidden
        // count); offline counts visible successors only (0 with
        // `is_current` 1) — required, so a hidden count never ships.
        {
            use crate::member_offline_fixtures::ACCT_B;

            let dir_b = tempfile::tempdir().expect("tempdir");
            let (member_b, lifecycle_b) =
                admit_member_copy_of(&dir_b, &world.db, ACCT_B, SCOPE).await;
            let mut offline_b = ToolRegistry::new();
            register_builtin_tools(&mut offline_b).expect("builtins");
            register_surface_tools(&mut offline_b).expect("surface");
            offline_b.set_member_copy_gate(lifecycle_b, SCOPE.to_owned(), 1, Vec::new());
            let sql = format!(
                "SELECT is_current, successor_count FROM records WHERE id = '{}'",
                two_caller::OLD_RECORD
            );
            let online_b = query_sql_value(&online, &world.db, ACCT_B, &sql).await;
            let offline_b_result = query_sql_value(&offline_b, &member_b, ACCT_B, &sql).await;
            assert_eq!(
                online_b["rows"],
                json!([{ "is_current": null, "successor_count": 1 }]),
                "online counts the hidden successor"
            );
            assert_eq!(
                offline_b_result["rows"],
                json!([{ "is_current": 1, "successor_count": 0 }]),
                "offline counts visible successors only"
            );
            member_b.close().await;
        }

        // Joins, aggregates and bound parameters over the slice.
        let joined = "SELECT l.relationship AS rel, count(*) AS c FROM links l \
            JOIN records r ON r.id = l.source_id GROUP BY l.relationship ORDER BY rel";
        assert_eq!(
            query_sql_value(&offline, &member_db, ACCT_A, joined).await["rows"],
            query_sql_value(&online, &world.db, ACCT_A, joined).await["rows"],
            "join/count parity"
        );
        let param = serde_json::to_value(crate::query::sql_contract::QuerySqlParameter::Text {
            value: Some(two_caller::SHARED_CHILD.to_owned()),
        })
        .expect("parameter");
        let by_id = offline
            .call(
                member_db.clone(),
                Caller::authenticated(ACCT_A),
                "query_sql",
                json!({
                    "sql": "SELECT id FROM records WHERE id = ?1",
                    "parameters": [param],
                }),
            )
            .await
            .expect("parameter query");
        assert_eq!(by_id["rows"], json!([{ "id": two_caller::SHARED_CHILD }]));

        // Authored aliases and counter-like cells survive verbatim.
        let literal = "SELECT 1 AS seq, 'rec:123' AS a, 'obs:456' AS b";
        assert_eq!(
            query_sql_value(&offline, &member_db, ACCT_A, literal).await["rows"],
            json!([{ "seq": 1, "a": "rec:123", "b": "obs:456" }]),
        );

        // Compiled catalog identical for every caller, never shipped data
        // (columns and rows; the envelope still omits `as_of_seq` offline).
        for sql in [
            "SELECT * FROM catalog_relations ORDER BY relation_name",
            "SELECT * FROM catalog_columns ORDER BY relation_name, column_position",
        ] {
            let online_catalog = query_sql_value(&online, &world.db, ACCT_A, sql).await;
            let offline_catalog = query_sql_value(&offline, &member_db, ACCT_A, sql).await;
            assert_eq!(
                offline_catalog["columns"], online_catalog["columns"],
                "catalog columns must be identical for {sql}"
            );
            assert_eq!(
                offline_catalog["rows"], online_catalog["rows"],
                "catalog rows must be identical for {sql}"
            );
            assert!(offline_catalog.get("as_of_seq").is_none());
        }

        // Hidden, deleted and missing are one answer: zero rows either way.
        for id in [two_caller::B_ONLY, "00000000-0000-4000-8000-000000000000"] {
            let sql = format!("SELECT id FROM records WHERE id = '{id}'");
            assert_eq!(
                query_sql_value(&offline, &member_db, ACCT_A, &sql).await["rows"],
                json!([]),
            );
            assert_eq!(
                query_sql_value(&online, &world.db, ACCT_A, &sql).await["rows"],
                json!([]),
            );
        }

        member_db.close().await;
    }

    /// Rev 8 §2.3 `query_sql` refusal: every excluded relation denies at
    /// prepare with the typed `UnavailableOffline` naming the relation —
    /// including column-less `COUNT(*)`/`EXISTS` and `WHERE 0`/`LIMIT 0` —
    /// never a missing-table error or an empty answer. Same-named CTEs and
    /// forbidden words in strings/comments still serve.
    #[tokio::test]
    async fn member_query_sql_refuses_excluded_at_prepare() {
        use crate::mcp::registry::{Caller, ToolRegistry};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());

        for (sql, requirement) in [
            ("SELECT local_seq FROM content_events", "content_events"),
            ("SELECT count(*) AS c FROM content_events", "content_events"),
            (
                "SELECT count(*) AS c FROM content_events WHERE 0",
                "content_events",
            ),
            (
                "SELECT * FROM content_events WHERE 0 LIMIT 0",
                "content_events",
            ),
            (
                "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM content_events)",
                "content_events",
            ),
            (
                "SELECT event_seq FROM facet_observations",
                "facet_observations",
            ),
            (
                "SELECT count(*) AS c FROM facet_observations",
                "facet_observations",
            ),
            (
                "SELECT config_id FROM schema_config_json_nodes",
                "schema_config_json_nodes",
            ),
            (
                "SELECT count(*) AS c FROM schema_config_json_nodes",
                "schema_config_json_nodes",
            ),
            (
                "SELECT count(*) AS c FROM schema_config_json_nodes WHERE 0",
                "schema_config_json_nodes",
            ),
            (
                "SELECT * FROM schema_config_json_nodes WHERE 0 LIMIT 0",
                "schema_config_json_nodes",
            ),
            (
                "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM schema_config_json_nodes)",
                "schema_config_json_nodes",
            ),
            ("SELECT count(*) AS c FROM body_blocks", "body_blocks"),
            (
                "SELECT title FROM body_block_headings",
                "body_block_headings",
            ),
            (
                "SELECT count(*) AS c FROM body_block_headings",
                "body_block_headings",
            ),
            (
                "SELECT count(*) AS c FROM body_block_headings WHERE 0",
                "body_block_headings",
            ),
            (
                "SELECT * FROM body_block_headings LIMIT 0",
                "body_block_headings",
            ),
            (
                "SELECT EXISTS(SELECT 1 FROM body_block_headings) AS n",
                "body_block_headings",
            ),
            (
                "SELECT count(*) AS c FROM body_blocks WHERE 0",
                "body_blocks",
            ),
            ("SELECT * FROM body_blocks LIMIT 0", "body_blocks"),
            (
                "SELECT id FROM records WHERE EXISTS (SELECT 1 FROM body_blocks)",
                "body_blocks",
            ),
            ("SELECT actor FROM actors", "actors"),
            ("SELECT count(*) AS c FROM actors", "actors"),
            ("SELECT count(*) AS c FROM agent_activity", "agent_activity"),
            (
                "SELECT count(*) AS c FROM agent_activity_claims",
                "agent_activity_claims",
            ),
            (
                "SELECT message_id FROM messages_awaiting_reply",
                "messages_awaiting_reply",
            ),
            (
                "SELECT count(*) AS c FROM messages_awaiting_reply",
                "messages_awaiting_reply",
            ),
            (
                "SELECT relationship_id FROM effective_relationships",
                "effective_relationships",
            ),
            (
                "SELECT ordinal FROM effective_relationship_endpoints",
                "effective_relationship_endpoints",
            ),
            (
                "SELECT count(*) AS c FROM effective_relationship_endpoints",
                "effective_relationship_endpoints",
            ),
            (
                "SELECT e.id FROM content_events e JOIN actors a USING (actor)",
                "actors",
            ),
        ] {
            // Typed requirement at the port: the authorizer denial names the
            // relation before any storage access.
            let request = crate::query::sql_contract::QuerySqlRequest {
                sql: sql.to_owned(),
                parameters: Vec::new(),
            };
            let error = crate::query::sql::query_sql_request_owned(
                member_db.clone(),
                crate::query::QueryPrincipal::authenticated(ACCT_A, true),
                request,
            )
            .await
            .expect_err(format!("must refuse: {sql}").as_str());
            assert!(
                matches!(&error, Error::UnavailableOffline { surface, requirement: got }
                    if surface == "query_sql" && got == requirement),
                "typed UnavailableOffline(query_sql, {requirement}) for {sql}, got {error:?}"
            );
            assert_refusal_clean(&error);
            // End to end through the registry: a refusal, never an empty
            // answer or a missing-table error (the registry stringifies the
            // typed error across the MCP boundary).
            let error = offline
                .call(
                    member_db.clone(),
                    Caller::authenticated(ACCT_A),
                    "query_sql",
                    json!({ "sql": sql }),
                )
                .await
                .expect_err(format!("must refuse: {sql}").as_str());
            let text = error.to_string();
            assert!(
                text.contains("unavailable_offline"),
                "registry refusal must stay unavailable_offline for {sql}, got {text:?}"
            );
            assert!(
                !text.contains("no such table"),
                "never a missing-table error for {sql}, got {text:?}"
            );
        }

        // No false classification of CTE aliases, comments or literals:
        // offline matches online outcome for each shape — serving with
        // equal rows where the shared two-phase validator accepts it, and
        // refusing where it rejects it (no grammar expansion either way).
        // The probe itself never mistakes these for forbidden relations
        // (unit-tested in `query::sql`); this asserts the end-to-end shape.
        for sql in [
            "WITH schema_config_json_nodes AS (SELECT 1 AS x) SELECT count(*) AS c FROM schema_config_json_nodes",
            "SELECT 'schema_config_json_nodes' AS v",
            "SELECT id FROM records -- schema_config_json_nodes",

            "WITH content_events AS (SELECT 1 AS x) SELECT count(*) AS c FROM content_events",
            "WITH actors AS (SELECT id FROM records) SELECT id FROM actors",
            "SELECT 'content_events' AS v",
            "SELECT id FROM records -- facet_observations",
        ] {
            let online_outcome = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_A),
                    "query_sql",
                    json!({ "sql": sql }),
                )
                .await;
            let offline_outcome = offline
                .call(
                    member_db.clone(),
                    Caller::authenticated(ACCT_A),
                    "query_sql",
                    json!({ "sql": sql }),
                )
                .await;
            match online_outcome {
                Ok(online_value) => {
                    let offline_value = offline_outcome.unwrap_or_else(|error| {
                        panic!("must serve where online serves ({sql}): {error:?}")
                    });
                    assert_eq!(
                        offline_value["rows"], online_value["rows"],
                        "rows must match for {sql}"
                    );
                }
                Err(_) => {
                    assert!(
                        offline_outcome.is_err(),
                        "must refuse where online refuses ({sql})"
                    );
                }
            }
        }

        member_db.close().await;
    }

    /// Over-shipment detector for `query_sql`: a hidden row planted in the
    /// staged copy (with digest and bytes fixed so admission accepts it) is
    /// served offline while online-as-the-member returns zero rows, so the
    /// differential catches the wrong slice instead of masking it.
    #[tokio::test]
    async fn member_query_sql_overshipment_is_caught_by_the_differential() {
        use crate::holding::ReplicaScope;
        use crate::mcp::registry::ToolRegistry;
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_copy_admission::{admit_member_copy, ExpectedFooting};
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        use sha2::Digest as _;

        let world = two_caller::build().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let staged = dir.path().join("staged.db");
        let request = crate::member_copy_producer::MemberCopyRequest {
            member_account: ACCT_A.to_owned(),
            scope_ref: SCOPE.to_owned(),
            hosted_route_database_id: "route-test".to_owned(),
            ordinal: 1,
            consumer: consumer_identity(),
            out_path: staged.clone(),
        };
        let mut copy = crate::member_copy_producer::build_member_copy(&world.db, request)
            .await
            .expect("producer");
        {
            let connection = rusqlite::Connection::open(&staged).expect("sqlite");
            connection
                .execute_batch(&format!(
                    "INSERT INTO records (id, type, kind, name, body, persistence, created_at, updated_at, archived) \
                     VALUES ('{}','Document','note','{}','b-only note','enduring','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z',0);",
                    two_caller::B_ONLY, two_caller::B_ONLY,
                ))
                .expect("plant hidden row");
            let digest = crate::member_digest::content_digest(&connection).expect("digest");
            drop(connection);
            copy.content_digest = digest.clone();
            copy.manifest.content_digest = digest;
            let bytes = std::fs::read(&staged).expect("bytes");
            copy.manifest.bytes.size_bytes = bytes.len() as u64;
            copy.manifest.bytes.sha256 = hex::encode(sha2::Sha256::digest(&bytes));
        }
        let copy_root = dir.path().join("copy");
        std::fs::create_dir_all(&copy_root).expect("copy root");
        let mut lifecycle = MemberCopyLifecycle::open(&copy_root).expect("lifecycle");
        lifecycle
            .sign_in(
                "acct",
                ReconnectAnswer::Replace {
                    cut_at: CUT.to_owned(),
                },
            )
            .expect("sign in");
        let scope_ref = match &copy.manifest.scope {
            ReplicaScope::Member { scope_ref } => scope_ref.clone(),
            ReplicaScope::Everything => panic!("member scope expected"),
        };
        let admitted = admit_member_copy(
            &copy_root,
            &staged,
            &serde_json::to_vec(&copy.manifest).expect("manifest json"),
            None,
            &ExpectedFooting {
                origin_database_id: copy.manifest.origin_database_id.clone(),
                scope_ref,
                consumer: copy.manifest.consumer.clone(),
            },
            &mut lifecycle,
        )
        .expect("admission accepts the digest-fixed oversized slice");
        let member_db = crate::db::open_member_database_read_only(
            admitted
                .generation_dir
                .join("snapshot.db")
                .to_str()
                .expect("path"),
        )
        .await
        .expect("member open");

        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).expect("builtins");
        register_surface_tools(&mut online).expect("surface");
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).expect("builtins");
        register_surface_tools(&mut offline).expect("surface");
        offline.set_member_copy_gate(
            Arc::new(Mutex::new(lifecycle)),
            SCOPE.to_owned(),
            1,
            Vec::new(),
        );

        let sql = format!("SELECT id FROM records WHERE id = '{}'", two_caller::B_ONLY);
        let online_rows = query_sql_value(&online, &world.db, ACCT_A, &sql).await["rows"].clone();
        let offline_rows =
            query_sql_value(&offline, &member_db, ACCT_A, &sql).await["rows"].clone();
        assert_eq!(online_rows, json!([]), "online-as-A hides B_ONLY");
        assert_ne!(
            offline_rows, online_rows,
            "the differential must detect an over-shipped hidden row"
        );

        member_db.close().await;
    }

    #[tokio::test]
    async fn member_engine_info_uses_local_build_data_and_explicit_policy_marker() {
        use crate::mcp::register_builtin_tools;
        use crate::member_offline_fixtures::{two_caller, ACCT_A};
        let world = two_caller::build().await;
        let dir = tempfile::tempdir().unwrap();
        let (member_db, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_A, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).unwrap();
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).unwrap();
        offline.set_member_copy_gate(lifecycle.clone(), SCOPE.into(), 1, Vec::new());
        let online_info = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_A),
                "engine_info",
                json!({}),
            )
            .await
            .unwrap();
        let member_info = offline
            .call(
                member_db.clone(),
                Caller::authenticated(ACCT_A),
                "engine_info",
                json!({}),
            )
            .await
            .unwrap();
        let policy_tables: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE name='storage_portability_policy'",
        )
        .fetch_one(member_db.pool())
        .await
        .unwrap();
        assert_eq!(
            policy_tables, 0,
            "success must not depend on a fake policy table"
        );
        for field in ["engine", "engine_version", "git_sha", "query_sql"] {
            assert_eq!(
                member_info[field], online_info[field],
                "build-owned {field}"
            );
        }
        assert_eq!(member_info["runtime"]["mode"], "member_copy");
        assert_eq!(
            member_info["runtime"]["profile"],
            crate::replica_generation::ReplicaProfile::MemberReadV1 {
                member_schema_digest: crate::schema::member_schema::member_schema_digest(),
            }
            .profile_id()
        );
        assert_eq!(member_info["runtime"]["writes_supported"], false);
        assert_eq!(
            member_info["storage_profile"]["policy"],
            json!({"unavailable_offline": {
                "surface":"engine_info.storage_policy", "retry":"when_online"
            }})
        );
        assert!(member_info["storage_profile"]
            .get("policy_revision")
            .is_none());
        assert!(online_info["storage_profile"].get("policy").is_none());
        assert_eq!(online_info["storage_profile"]["enforcement"], "off");
        let context = serde_json::to_value(HoldingDisclosureV2::member(SCOPE.into(), 1)).unwrap();
        assert_eq!(member_info["standby_context"], context);
        let ping = offline
            .call(
                member_db.clone(),
                Caller::authenticated(ACCT_A),
                "ping",
                json!({}),
            )
            .await
            .unwrap();
        assert_eq!(ping["ok"], true);
        assert_eq!(ping["standby_context"], context);
        assert_no_counter_fields(&member_info, "member engine info");
        assert_no_counter_fields(&ping, "member ping");
        member_db.close().await;
        world.db.close().await;
    }

    #[tokio::test]
    async fn member_structure_matches_visible_tree_caps_and_redacted_orphan() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{grant, mk_doc, two_caller, ACCT_A, ACCT_B};
        let world = two_caller::build().await;
        let visible = "c6000000-0000-4000-8000-000000000001";
        let hidden = "c6000000-0000-4000-8000-000000000002";
        let archived = "c6000000-0000-4000-8000-000000000003";
        let deleted = "c6000000-0000-4000-8000-000000000004";
        for id in [visible, hidden, archived, deleted] {
            mk_doc(&world.db, id, two_caller::SHARED, None, None).await;
        }
        grant(
            &world.db,
            hidden,
            vec![AllowEntry::account(ACCT_A, Capability::View)],
        )
        .await;
        crate::store::update_record(&world.db, visible, json!({"name":"seq rec:123 obs:456"}))
            .await
            .unwrap();
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).unwrap();
        register_surface_tools(&mut online).unwrap();
        for (tool, id) in [("archive_record", archived), ("delete_record", deleted)] {
            online
                .call(
                    world.db.clone(),
                    Caller::local(),
                    tool,
                    json!({"id":id, "reason":"member structure fixture"}),
                )
                .await
                .unwrap();
        }
        let dir = tempfile::tempdir().unwrap();
        let (member, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_B, SCOPE).await;
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).unwrap();
        register_surface_tools(&mut offline).unwrap();
        offline.set_member_copy_gate(lifecycle, SCOPE.into(), 1, Vec::new());
        let orphan_home: Option<String> =
            sqlx::query_scalar("SELECT home_id FROM records WHERE id=?")
                .bind(two_caller::VISIBLE_CHILD)
                .fetch_one(member.pool())
                .await
                .unwrap();
        assert_eq!(orphan_home, None);
        let orphan = compare_member_structure(
            &online,
            &offline,
            &world.db,
            &member,
            ACCT_B,
            json!({"root_id":two_caller::VISIBLE_CHILD}),
        )
        .await;
        assert_eq!(orphan["nodes"][0]["containment_path_visible"], false);
        assert!(!orphan.to_string().contains(two_caller::HIDDEN_PARENT));
        for args in [
            json!({"root_id":two_caller::SHARED}),
            json!({"root_id":two_caller::SHARED,"max_depth":0}),
            json!({"root_id":two_caller::SHARED,"max_children_per_node":1}),
            json!({"root_id":two_caller::SHARED,"max_children_per_node":0}),
            json!({"root_id":two_caller::SHARED,"include_archived":true}),
            json!({"root_id":two_caller::SHARED,"exclude_types":["Document"]}),
        ] {
            let output = compare_member_structure(
                &online,
                &offline,
                &world.db,
                &member,
                ACCT_B,
                args.clone(),
            )
            .await;
            if args.get("exclude_types").is_none() {
                assert!(output["nodes"][0]["child_count"].as_i64().unwrap() >= 2);
            } else {
                assert_eq!(output["nodes"][0]["child_count"], 0);
                assert_eq!(output["nodes"].as_array().unwrap().len(), 1);
            }
            if args["max_depth"] == 0 || args["max_children_per_node"] == 0 {
                assert_eq!(output["nodes"].as_array().unwrap().len(), 1);
            }
            if args["max_children_per_node"] == 1 {
                assert_eq!(output["nodes"].as_array().unwrap().len(), 2);
            }
            let has_archived = output["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|node| node["id"] == archived);
            if args["include_archived"] == true {
                assert!(
                    has_archived,
                    "archive variant must change the returned tree"
                );
            } else {
                assert!(!has_archived);
            }
        }
        let full = compare_member_structure(
            &online,
            &offline,
            &world.db,
            &member,
            ACCT_B,
            json!({"root_id":two_caller::SHARED}),
        )
        .await;
        assert!(full["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|node| node["name"] == "seq rec:123 obs:456"));
        for id in [hidden, deleted, "c6000000-0000-4000-8000-000000000099"] {
            let args = json!({"root_id":id});
            let expected = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_B),
                    "get_structure",
                    args.clone(),
                )
                .await
                .unwrap_err()
                .to_string();
            let actual = offline
                .call(
                    member.clone(),
                    Caller::authenticated(ACCT_B),
                    "get_structure",
                    args,
                )
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(actual.replace(id, "<id>"), expected.replace(id, "<id>"));
        }
        let refused = offline
            .call(
                member.clone(),
                Caller::authenticated(ACCT_B),
                "get_structure",
                json!({"root_id":two_caller::SHARED,"as_of":{"act":1}}),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(refused, Error::UnavailableOffline { ref requirement, .. } if requirement == "as_of")
        );
        member.close().await;
        world.db.close().await;
    }

    async fn compare_member_structure(
        online: &ToolRegistry,
        offline: &ToolRegistry,
        source: &crate::Db,
        member: &crate::Db,
        account: &str,
        args: Value,
    ) -> Value {
        let mut expected = online
            .call(
                source.clone(),
                Caller::authenticated(account),
                "get_structure",
                args.clone(),
            )
            .await
            .unwrap();
        let mut actual = offline
            .call(
                member.clone(),
                Caller::authenticated(account),
                "get_structure",
                args,
            )
            .await
            .unwrap();
        let marker =
            json!({"unavailable_offline":{"surface":"custody_boundary", "retry":"when_online"}});
        let oracle = crate::member_offline_fixtures::online_visible_ids(source, account).await;
        assert!(
            !actual["nodes"].as_array().unwrap().is_empty(),
            "visible root must be emitted"
        );
        for node in actual["nodes"].as_array().unwrap() {
            assert!(oracle.contains(node["id"].as_str().unwrap()));
            assert_eq!(node["custody_boundary"], marker);
        }
        for node in expected["nodes"].as_array_mut().unwrap() {
            node["custody_boundary"] = marker.clone();
        }
        assert_no_counter_fields(&actual, "member structure");
        actual.as_object_mut().unwrap().remove("standby_context");
        assert_eq!(
            actual, expected,
            "structure fields and counts must match online"
        );
        actual
    }

    async fn compare_member_attachment_answer(
        online: &ToolRegistry,
        offline: &ToolRegistry,
        source: &crate::db::Db,
        member: &crate::db::Db,
        account: &str,
        tool: &str,
        args: Value,
    ) -> Value {
        let expected = online
            .call(
                source.clone(),
                Caller::authenticated(account),
                tool,
                args.clone(),
            )
            .await
            .unwrap();
        let mut actual = offline
            .call(member.clone(), Caller::authenticated(account), tool, args)
            .await
            .unwrap();
        // Byte content and filenames are authored payload at known attachment
        // positions. Keep metadata siblings covered by the counter detector.
        let mut metadata = actual.clone();
        if tool == "read_attachment" {
            metadata.as_object_mut().unwrap().remove("content");
        }
        if let Some(blob) = metadata.get_mut("blob").and_then(Value::as_object_mut) {
            blob.remove("original_filename");
        }
        if let Some(rows) = metadata
            .get_mut("attachments")
            .and_then(Value::as_array_mut)
        {
            for row in rows {
                row.as_object_mut().unwrap().remove("original_filename");
            }
        }
        assert_no_counter_fields(&metadata, "member attachment metadata");
        actual.as_object_mut().unwrap().remove("standby_context");
        assert_eq!(actual, expected, "full attachment answer parity: {tool}");
        actual
    }

    #[tokio::test]
    async fn member_attachments_preserve_inline_bytes_and_external_metadata() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{
            attach_inline, online_visible_ids, two_caller, ACCT_B,
        };
        let world = two_caller::build().await;
        let text_id = "c6b00000-0000-4000-8000-000000000001";
        let binary_id = "c6b00000-0000-4000-8000-000000000002";
        let deleted_id = "c6b00000-0000-4000-8000-000000000003";
        let text_bytes = b"seq rec:123 obs:456 retained bytes";
        for (id, bytes) in [
            (text_id, text_bytes.as_slice()),
            (binary_id, &[0xff, 0, 42, 0xfe][..]),
            (deleted_id, &b"withdrawn bytes"[..]),
        ] {
            let blob_id = attach_inline(
                &world.db,
                id,
                two_caller::SHARED_CHILD,
                vec![AllowEntry::members(Capability::View)],
                bytes,
            )
            .await;
            if id == text_id {
                sqlx::query("UPDATE blobs SET original_filename='obs:456' WHERE id=?")
                    .bind(&blob_id)
                    .execute(world.db.write_pool())
                    .await
                    .unwrap();
            }
            if id == binary_id {
                sqlx::query("UPDATE blobs SET mime='application/octet-stream' WHERE id=?")
                    .bind(blob_id)
                    .execute(world.db.write_pool())
                    .await
                    .unwrap();
            }
        }
        crate::store::update_record(&world.db, text_id, json!({"name":"seq rec:123 obs:456"}))
            .await
            .unwrap();
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).unwrap();
        register_surface_tools(&mut online).unwrap();
        online
            .call(
                world.db.clone(),
                Caller::local(),
                "manage_attachments",
                json!({"action":"detach", "attachment_id":deleted_id}),
            )
            .await
            .unwrap();
        let oracle = online_visible_ids(&world.db, ACCT_B).await;
        for id in [text_id, binary_id, two_caller::EXT_ATTACH] {
            assert!(oracle.contains(id));
        }
        for id in [deleted_id, two_caller::ATT_A] {
            assert!(!oracle.contains(id));
        }
        let dir = tempfile::tempdir().unwrap();
        let (member, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_B, SCOPE).await;
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).unwrap();
        register_surface_tools(&mut offline).unwrap();
        offline.set_member_copy_gate(lifecycle, SCOPE.into(), 1, Vec::new());
        for (record_id, minimum) in [(two_caller::SHARED_CHILD, 2), (two_caller::OLD_RECORD, 1)] {
            let listed = compare_member_attachment_answer(
                &online,
                &offline,
                &world.db,
                &member,
                ACCT_B,
                "manage_attachments",
                json!({"action":"list","record_id":record_id}),
            )
            .await;
            let rows = listed["attachments"].as_array().unwrap();
            assert!(rows.len() >= minimum);
            for row in rows {
                assert!(oracle.contains(row["attachment_id"].as_str().unwrap()));
            }
            assert!(!listed.to_string().contains(two_caller::ATT_A));
        }
        for id in [text_id, binary_id, two_caller::EXT_ATTACH] {
            let inspected = compare_member_attachment_answer(
                &online,
                &offline,
                &world.db,
                &member,
                ACCT_B,
                "manage_attachments",
                json!({"action":"inspect","attachment_id":id}),
            )
            .await;
            assert!(inspected["blob"]["size_bytes"].as_i64().unwrap() > 0);
            assert!(inspected["blob"].get("external_ref").is_none());
        }
        for args in [
            json!({"attachment_id":text_id}),
            json!({"attachment_id":text_id,"offset":4,"length":7}),
            json!({"attachment_id":text_id,"offset":text_bytes.len(),"length":5}),
            json!({"attachment_id":binary_id}),
        ] {
            let read = compare_member_attachment_answer(
                &online,
                &offline,
                &world.db,
                &member,
                ACCT_B,
                "read_attachment",
                args.clone(),
            )
            .await;
            if args["attachment_id"] == binary_id {
                assert_eq!(read["content_encoding"], "base64");
                assert_eq!(read["content"], "/wAq/g==");
            } else if args.get("offset").is_none() {
                assert_eq!(read["content"], std::str::from_utf8(text_bytes).unwrap());
                assert_eq!(read["name"], "seq rec:123 obs:456");
                assert_eq!(read["length"], text_bytes.len());
                assert_eq!(read["eof"], true);
            } else if args["offset"] == text_bytes.len() {
                assert_eq!(read["length"], 0);
                assert_eq!(read["content"], "");
                assert_eq!(read["eof"], true);
            } else {
                assert_eq!(read["length"], 7);
                assert_eq!(read["eof"], false);
            }
        }
        let external = offline
            .call(
                member.clone(),
                Caller::authenticated(ACCT_B),
                "read_attachment",
                json!({"attachment_id":two_caller::EXT_ATTACH}),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(external, Error::NotHeld(_)),
            "external bytes must be typed not held"
        );
        assert!(online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "read_attachment",
                json!({"attachment_id":two_caller::EXT_ATTACH})
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("stored externally"));
        for id in [
            two_caller::ATT_A,
            deleted_id,
            "c6b00000-0000-4000-8000-000000000099",
        ] {
            for (tool, args) in [
                ("read_attachment", json!({"attachment_id":id})),
                (
                    "manage_attachments",
                    json!({"action":"inspect","attachment_id":id}),
                ),
            ] {
                let expected = online
                    .call(
                        world.db.clone(),
                        Caller::authenticated(ACCT_B),
                        tool,
                        args.clone(),
                    )
                    .await
                    .unwrap_err()
                    .to_string();
                let actual = offline
                    .call(member.clone(), Caller::authenticated(ACCT_B), tool, args)
                    .await
                    .unwrap_err()
                    .to_string();
                assert_eq!(actual, expected, "uniform absent attachment");
            }
        }
        let write = offline
            .call(
                member.clone(),
                Caller::authenticated(ACCT_B),
                "manage_attachments",
                json!({"action":"detach","attachment_id":text_id}),
            )
            .await
            .unwrap_err();
        assert!(matches!(write, Error::StandbyReadOnly { .. }));
        member.close().await;
        world.db.close().await;
    }

    #[tokio::test]
    async fn member_links_page_visible_edges_and_bind_cursors() {
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{
            link, online_visible_ids, two_caller, ACCT_A, ACCT_B,
        };
        let world = two_caller::build().await;
        for (id, target) in [
            ("zz-c6b-visible-link-1", two_caller::OLD_RECORD),
            ("zz-c6b-visible-link-2", two_caller::SHARED),
        ] {
            link(&world.db, id, two_caller::SHARED_CHILD, target, "mentions").await;
        }
        let oracle = online_visible_ids(&world.db, ACCT_B).await;
        assert!(oracle.contains(two_caller::SHARED_CHILD));
        assert!(oracle.contains(two_caller::OLD_RECORD));
        assert!(!oracle.contains(two_caller::HIDDEN_PARENT));
        let dir = tempfile::tempdir().unwrap();
        let (member, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_B, SCOPE).await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).unwrap();
        register_surface_tools(&mut online).unwrap();
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).unwrap();
        register_surface_tools(&mut offline).unwrap();
        offline.set_member_copy_gate(lifecycle, SCOPE.into(), 1, Vec::new());
        let args = json!({"action":"list","record_id":two_caller::SHARED_CHILD,"limit":1});
        let first_online = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "manage_links",
                args.clone(),
            )
            .await
            .unwrap();
        // Non-vacuous REV10 exception: online consumes the hidden physical row.
        assert_eq!(first_online["returned"], 0);
        assert_eq!(first_online["has_more"], true);
        let first = offline
            .call(
                member.clone(),
                Caller::authenticated(ACCT_B),
                "manage_links",
                args.clone(),
            )
            .await
            .unwrap();
        assert_eq!(first["returned"], 1);
        assert_eq!(first["has_more"], true);
        assert_eq!(first["links_out"][0]["id"], "zz-c6b-visible-link-1");
        assert!(first["links_in"].as_array().unwrap().is_empty());
        let cursor = first["next_cursor"].as_str().unwrap();
        assert!(!cursor.contains("zz-c6b"));
        for bad in [
            json!({"action":"list","record_id":two_caller::SHARED_CHILD,"limit":2,"cursor":cursor}),
            json!({"action":"list","record_id":two_caller::OLD_RECORD,"limit":1,"cursor":cursor}),
            json!({"action":"list","record_id":two_caller::SHARED_CHILD,"limit":1,"cursor":"unknown-cursor"}),
        ] {
            let error = offline
                .call(
                    member.clone(),
                    Caller::authenticated(ACCT_B),
                    "manage_links",
                    bad,
                )
                .await
                .unwrap_err()
                .to_string();
            assert!(error.contains("cursor_reset_required"), "{error}");
        }
        let foreign = offline.call(member.clone(), Caller::authenticated(ACCT_A), "manage_links", json!({"action":"list","record_id":two_caller::SHARED_CHILD,"limit":1,"cursor":cursor})).await.unwrap_err().to_string();
        assert!(foreign.contains("cursor_reset_required"), "{foreign}");
        let second = offline
            .call(
                member.clone(),
                Caller::authenticated(ACCT_B),
                "manage_links",
                first["next_call"].clone(),
            )
            .await
            .unwrap();
        assert_eq!(second["returned"], 1);
        assert_eq!(second["has_more"], false);
        assert!(second["next_cursor"].is_null());
        assert_eq!(second["links_out"][0]["id"], "zz-c6b-visible-link-2");
        let all_args = json!({"action":"list","record_id":two_caller::SHARED_CHILD,"limit":200});
        let all_online = online
            .call(
                world.db.clone(),
                Caller::authenticated(ACCT_B),
                "manage_links",
                all_args.clone(),
            )
            .await
            .unwrap();
        let all_member = offline
            .call(
                member.clone(),
                Caller::authenticated(ACCT_B),
                "manage_links",
                all_args,
            )
            .await
            .unwrap();
        assert_eq!(all_member["links_out"], all_online["links_out"]);
        assert_eq!(all_member["links_in"], all_online["links_in"]);
        assert_eq!(all_member["returned"], 2);
        for page in [&first, &second, &all_member] {
            assert_no_counter_fields(page, "member link page");
            assert!(!page.to_string().contains(two_caller::HIDDEN_PARENT));
            for key in ["links_in", "links_out"] {
                for edge in page[key].as_array().unwrap() {
                    assert!(oracle.contains(edge["source_id"].as_str().unwrap()));
                    assert!(oracle.contains(edge["target_id"].as_str().unwrap()));
                }
            }
        }
        for id in [two_caller::HIDDEN_PARENT, "missing-link-anchor"] {
            let error = offline
                .call(
                    member.clone(),
                    Caller::authenticated(ACCT_B),
                    "manage_links",
                    json!({"action":"list","record_id":id}),
                )
                .await
                .unwrap_err()
                .to_string();
            let expected = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_B),
                    "manage_links",
                    json!({"action":"list","record_id":id}),
                )
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
        }
        let write = offline.call(member.clone(), Caller::authenticated(ACCT_B), "manage_links", json!({"action":"add","source_id":two_caller::SHARED_CHILD,"target_id":two_caller::OLD_RECORD,"relationship":"mentions"})).await.unwrap_err();
        assert!(matches!(write, crate::error::Error::StandbyReadOnly { .. }));
        // A new admitted serving Db has no access to the old Db's cursor cache.
        let next_dir = tempfile::tempdir().unwrap();
        let (next, _) = admit_member_copy_of(&next_dir, &world.db, ACCT_B, SCOPE).await;
        let reset = offline
            .call(
                next.clone(),
                Caller::authenticated(ACCT_B),
                "manage_links",
                first["next_call"].clone(),
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(reset.contains("cursor_reset_required"), "{reset}");
        next.close().await;
        member.close().await;
        world.db.close().await;
    }

    #[tokio::test]
    async fn member_dashboard_preserves_record_buckets_and_marks_excluded_sections() {
        use crate::authorization::{AllowEntry, Capability};
        use crate::mcp::{register_builtin_tools, register_surface_tools};
        use crate::member_offline_fixtures::{grant, online_visible_ids, two_caller, ACCT_B};
        let world = two_caller::build().await;
        let mut online = ToolRegistry::new();
        register_builtin_tools(&mut online).unwrap();
        register_surface_tools(&mut online).unwrap();
        let active = "f3000000-0000-4000-8000-000000000001";
        let stale = "f3000000-0000-4000-8000-000000000002";
        let hidden_blocked = "f3000000-0000-4000-8000-000000000003";
        let terminal = "f3000000-0000-4000-8000-000000000004";
        let unclassified = "f3000000-0000-4000-8000-000000000005";
        for (id, ty, kind, lifecycle, time) in [
            (
                active,
                "WorkItem",
                "task",
                "open",
                "2099-01-01T00:00:00.000Z",
            ),
            (
                stale,
                "WorkItem",
                "task",
                "open",
                "2000-01-01T00:00:00.000Z",
            ),
            (
                hidden_blocked,
                "WorkItem",
                "task",
                "open",
                "2001-01-01T00:00:00.000Z",
            ),
            (
                terminal,
                "WorkItem",
                "task",
                "completed",
                "2000-01-01T00:00:00.000Z",
            ),
            (
                unclassified,
                "Document",
                "note",
                "mystery",
                "2098-01-01T00:00:00.000Z",
            ),
        ] {
            crate::store::create_record(
                &world.db,
                json!({
                    "id": id, "type": ty, "kind": kind, "lifecycle": lifecycle,
                    "name": format!("dashboard seq rec:123 obs:456 {id}"),
                    "home_id": two_caller::SHARED,
                }),
            )
            .await
            .unwrap();
            grant(&world.db, id, vec![AllowEntry::members(Capability::View)]).await;
            sqlx::query("UPDATE records SET last_activity_at=? WHERE id=?")
                .bind(time)
                .bind(id)
                .execute(world.db.write_pool())
                .await
                .unwrap();
        }
        for (source, target) in [(stale, active), (two_caller::HIDDEN_PARENT, hidden_blocked)] {
            online.call(world.db.clone(), Caller::local(), "manage_links", json!({
                "action":"add", "source_id":source, "target_id":target, "relationship":"blocks"
            })).await.unwrap();
            let present: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM links WHERE source_id=? AND target_id=? AND relationship='blocks')"
            ).bind(source).bind(target).fetch_one(world.db.pool()).await.unwrap();
            assert!(
                present,
                "canonical fixture writer must project its blocks edge"
            );
        }
        // Link writers touch last_activity_at; restore the deliberate fixture dates.
        for (id, time) in [
            (stale, "2000-01-01T00:00:00.000Z"),
            (hidden_blocked, "2001-01-01T00:00:00.000Z"),
        ] {
            sqlx::query("UPDATE records SET last_activity_at=? WHERE id=?")
                .bind(time)
                .bind(id)
                .execute(world.db.write_pool())
                .await
                .unwrap();
        }
        let oracle = online_visible_ids(&world.db, ACCT_B).await;
        for id in [active, stale, hidden_blocked, terminal, unclassified] {
            assert!(oracle.contains(id));
        }
        assert!(!oracle.contains(two_caller::HIDDEN_PARENT));
        let dir = tempfile::tempdir().unwrap();
        let (member, lifecycle) = admit_member_copy_of(&dir, &world.db, ACCT_B, SCOPE).await;
        let mut offline = ToolRegistry::new();
        register_builtin_tools(&mut offline).unwrap();
        register_surface_tools(&mut offline).unwrap();
        offline.set_member_copy_gate(lifecycle, SCOPE.to_owned(), 1, Vec::new());
        for args in [
            json!({}),
            json!({"limit": 1}),
            json!({"scope": two_caller::SHARED, "limit": 1}),
        ] {
            let expected = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_B),
                    "get_dashboard",
                    args.clone(),
                )
                .await
                .unwrap();
            let mut actual = offline
                .call(
                    member.clone(),
                    Caller::authenticated(ACCT_B),
                    "get_dashboard",
                    args.clone(),
                )
                .await
                .unwrap();
            assert!(expected["active_total"].as_u64().unwrap() >= 2);
            assert_eq!(expected["stale_total"], 2);
            assert_eq!(expected["blocked_total"], 1);
            assert_eq!(expected["blocked"][0]["id"], active);
            assert_eq!(expected["blocked"][0]["blocked_by"][0]["id"], stale);
            assert_eq!(expected["unclassified_lifecycle"]["total_count"], 1);
            assert!(!expected["active"]
                .as_array()
                .unwrap()
                .iter()
                .chain(expected["stale"].as_array().unwrap())
                .any(|r| r["id"] == terminal));
            if args.get("limit").is_some() {
                assert_eq!(actual["active"].as_array().unwrap().len(), 1);
                assert_eq!(actual["stale"].as_array().unwrap().len(), 1);
                assert_eq!(actual["stale"][0]["id"], stale);
            }
            for key in ["active", "stale", "blocked"] {
                for row in actual[key].as_array().unwrap() {
                    assert!(oracle.contains(row["id"].as_str().unwrap()));
                    assert!(row["name"]
                        .as_str()
                        .unwrap()
                        .contains("seq rec:123 obs:456"));
                }
            }
            assert_no_counter_fields(&actual, "member dashboard");
            let text = crate::mcp::render::render("get_dashboard", &actual).unwrap();
            for section in ["claims", "runs"] {
                assert_eq!(
                    actual[section],
                    json!({"unavailable_offline": {
                        "surface": format!("get_dashboard.{section}"), "retry": "when_online"
                    }})
                );
                assert!(text.contains(&format!("get_dashboard.{section}")));
                actual.as_object_mut().unwrap().remove(section);
            }
            assert!(!text.contains(two_caller::HIDDEN_PARENT));
            actual.as_object_mut().unwrap().remove("standby_context");
            // Cutoff is the same wall-clock expression, evaluated at distinct calls.
            let mut expected = expected;
            assert!(actual["stale_cutoff"].is_string());
            assert!(expected["stale_cutoff"].is_string());
            actual.as_object_mut().unwrap().remove("stale_cutoff");
            expected.as_object_mut().unwrap().remove("stale_cutoff");
            assert_eq!(actual, expected, "dashboard full-field parity for {args}");
        }
        let mut errors = Vec::new();
        for root in [two_caller::HIDDEN_PARENT, "missing-dashboard-root"] {
            let error = offline
                .call(
                    member.clone(),
                    Caller::authenticated(ACCT_B),
                    "get_dashboard",
                    json!({"scope": root}),
                )
                .await
                .unwrap_err()
                .to_string();
            let expected = online
                .call(
                    world.db.clone(),
                    Caller::authenticated(ACCT_B),
                    "get_dashboard",
                    json!({"scope": root}),
                )
                .await
                .unwrap_err()
                .to_string();
            assert_eq!(error, expected);
            errors.push(error.replace(root, "<root>"));
        }
        assert_eq!(errors[0], errors[1]);
        member.close().await;
        world.db.close().await;
    }
}
