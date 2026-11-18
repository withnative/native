//! Constrained replay of single kernel writes inside a caller-owned
//! transaction: the seam a private working copy uses to rebase pending writes
//! (undo, fold an accepted delta, replay, commit once).
//!
//! A replay runs ONE allowlisted write through the ordinary validation and
//! receipt path ([`super::execute_transaction`] with no live context) inside
//! its OWN savepoint on the caller's transaction. It never begins, commits or
//! rolls back the outer transaction, never opens a write transaction of its
//! own, and never wakes realtime: the caller wakes realtime itself after its
//! outer commit (via `Db::commit_kernel_content` or equivalent).
//!
//! Outcomes are LOCAL only ([`ReplayOutcome`]): `Applied` carries the write
//! receipt the ordinary path produced, `LocallyRefused` carries the reason a
//! write did not run. A local refusal rolls back only the replay's savepoint
//! and leaves the outer transaction usable. Neither outcome is a hosted
//! verdict, and no receipt ledger or publication/bookkeeping table beyond the
//! ordinary write's own rows is touched here.

//! Private replay for the off-default installed working-copy manager. The
//! ordinary first-party append seam remains unchanged; minted creates require
//! the separate provider-captured execution context below.
#![allow(dead_code)]
use super::{execute_transaction, invalid, optional_text, text, view};
use crate::{db::Db, Result};
use serde_json::Value;
use sqlx::{Sqlite, SqliteConnection, Transaction};
use std::sync::atomic::{AtomicU64, Ordering};

/// The original admission identity a proposal was journalled under: the ambient
/// application claim and, for minted-ID writes, the mint context. Supplied by
/// the caller (the original journalled call), never derived from the
/// proposal's arguments, and conferring no authority: the actor is still
/// authenticated separately and the write is still re-authorized.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ProposalIdentity {
    /// Ambient application claim (`None` when the original call had none).
    pub app: Option<Value>,
    /// Mint context, present only for minted-ID writes.
    pub mint_context: Option<String>,
}

impl ProposalIdentity {
    /// True when neither half is set (a `None` app and no mint context).
    /// An explicit JSON null app counts as unset.
    fn is_null(&self) -> bool {
        self.app.as_ref().is_none_or(Value::is_null) && self.mint_context.is_none()
    }
}

/// Pure request fingerprint over (tool, args, identity): the exact identity
/// the proposal was journalled under, with no ambient dispatch consulted.
/// [`super::dispatched_fingerprint`] is a thin wrapper that selects the
/// identity from the current dispatch and calls this; it is the single
/// normalization path (via `intent_fingerprint`).
pub(crate) fn proposal_fingerprint(
    tool: &str,
    args: &Value,
    identity: &ProposalIdentity,
) -> Result<String> {
    let app = identity.app.clone().unwrap_or(Value::Null);
    let scoped = if matches!(tool, "create_record" | "attach_text" | "attach_from_url")
        && args.get("id_nonce").is_some()
    {
        match &identity.mint_context {
            Some(mint_context) => serde_json::json!({"app": app, "mint_context": mint_context}),
            None => app,
        }
    } else {
        app
    };
    super::intent_fingerprint(tool, args.clone(), scoped)
}

/// Original first-party create capture. Its execution context can only be
/// observed inside the authenticated provider dispatch, never supplied by a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RecordOperation {
    Create,
    Update,
    Archive,
    LinkAdd,
    LinkRemove,
}

/// Verify a family outcome on the grounded accepted cut, before any pending
/// original is replayed. The keyed fact is an identity/correlation witness;
/// its complete native act and historical subject states prove the effects.
/// This neither runs a write nor turns a working copy into an accepted one.
pub(crate) async fn record_materialized_on(
    conn: &mut SqliteConnection,
    actor: &str,
    operation: RecordOperation,
    args: &Value,
    receipt: &Value,
    fact_seq: i64,
    fact_act: i64,
) -> Result<bool> {
    let fail =
        || crate::Error::engine("record-family native materialization differs; full W retained");
    // The journal codec already validated the source and its exact provider
    // projection. Create args here include the provider-owned final ID/nonce.
    let id = operation.primary_target(args).ok_or_else(fail)?;
    if receipt["id"].as_str() != Some(id) || !receipt["changed"].is_boolean() {
        return Err(fail());
    }
    let expected_effect = match operation {
        RecordOperation::Create => receipt["effect"] == "created",
        RecordOperation::Update => {
            matches!(receipt["effect"].as_str(), Some("updated" | "unchanged"))
        }
        RecordOperation::Archive => true,
        RecordOperation::LinkAdd => matches!(
            receipt["effect"].as_str(),
            Some("link_added" | "link_note_updated" | "unchanged")
        ),
        RecordOperation::LinkRemove => matches!(
            receipt["effect"].as_str(),
            Some("link_removed" | "unchanged")
        ),
    };
    if !expected_effect
        || (receipt["changed"] == false
            && operation != RecordOperation::Archive
            && receipt["effect"] != "unchanged")
    {
        return Err(fail());
    }
    if matches!(
        operation,
        RecordOperation::LinkAdd | RecordOperation::LinkRemove
    ) && (receipt["source_id"].as_str() != Some(id)
        || receipt["target_id"] != args["target_id"]
        || receipt["relationship"] != args["relationship"]
        || receipt["action"] != args["action"])
    {
        return Err(fail());
    }
    type NativeEffect = (i64, String, String, Option<String>, String);
    let effects: Vec<NativeEffect> = sqlx::query_as(
        "SELECT seq,type,record_id,actor,payload FROM main.content_events WHERE act=? AND seq<? ORDER BY seq",
    ).bind(fact_act).bind(fact_seq).fetch_all(&mut *conn).await?;
    // One ordinary native call owns one act. Never group another keyed call or
    // an event after the keyed fact into this operation's proof.
    let after: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE act=? AND seq>?)",
    )
    .bind(fact_act)
    .bind(fact_seq)
    .fetch_one(&mut *conn)
    .await?;
    if after
        || effects.iter().any(|(_, kind, _, author, _)| {
            author.as_deref() != Some(actor) || kind == crate::kernel::mcp_write_receipts::EVENT
        })
    {
        return Err(fail());
    }
    let lower = effects
        .first()
        .map_or(fact_seq, |e| e.0)
        .checked_sub(1)
        .ok_or_else(fail)?;
    let before = crate::kernel::historical::record_at_on(conn, actor, id, lower).await?;
    let post = crate::kernel::historical::record_at_on(conn, actor, id, fact_seq)
        .await?
        .ok_or_else(fail)?;
    let requested_links: Vec<&Value> = if matches!(
        operation,
        RecordOperation::LinkAdd | RecordOperation::LinkRemove
    ) {
        vec![args]
    } else {
        args["links"]
            .as_array()
            .map(|v| v.iter().collect())
            .unwrap_or_default()
    };
    // Metadata/body/archive proofs need no endpoint-history scan. Unexpected
    // link effects still fail the complete-group check below.
    let (before_links, post_links) = if requested_links.is_empty() {
        (Vec::new(), Vec::new())
    } else {
        (
            crate::kernel::historical::links_at_on(conn, actor, id, lower).await?,
            crate::kernel::historical::links_at_on(conn, actor, id, fact_seq).await?,
        )
    };
    // Provider relationships have their own native aggregates. Their receipts
    // cannot be mistaken for a directed-link proof here.
    if requested_links.iter().any(|link| {
        link["relationship"]
            .as_str()
            .is_none_or(crate::v2_standard::relates_to::reserves)
    }) {
        return Err(fail());
    }
    let matches_link = |link: &Value, request: &Value| {
        link["source_id"].as_str() == Some(id)
            && link["target_id"] == request["target_id"]
            && link["relationship"] == request["relationship"]
    };
    let mut creation = None;
    for (_, kind, record, _, raw) in &effects {
        let payload: Value = serde_json::from_str(raw)?;
        match kind.as_str() {
            "kernel.record_created.v1"
                if operation == RecordOperation::Create && record == id && creation.is_none() =>
            {
                creation = Some(payload)
            }
            "kernel.record_revised.v1" | "kernel.record_revised.v2"
                if operation == RecordOperation::Update && record == id =>
            {
                let fields = payload["fields"].as_object().ok_or_else(fail)?;
                if fields.keys().any(|key| match key.as_str() {
                    "title" => args.get("name").is_none(),
                    "summary" | "lifecycle" => args.get(key).is_none(),
                    _ => true,
                }) {
                    return Err(fail());
                }
            }
            "kernel.body_set.v1"
                if record == id
                    && ["body", "body_set", "body_append", "body_replace"]
                        .iter()
                        .any(|key| args.get(*key).is_some()) => {}
            "kernel.metadata_set.v1" if record == id => {
                let patch = payload.as_object().ok_or_else(fail)?;
                if patch.keys().any(|key| {
                    !matches!(key.as_str(), "basis" | "origin")
                        && (!matches!(key.as_str(), "persistence" | "maturity")
                            || args.get(key).is_none())
                }) {
                    return Err(fail());
                }
            }
            "kernel.record_rehomed.v1" | "kernel.record_rehomed.v2"
                if operation == RecordOperation::Update
                    && record == id
                    && args.get("home_id").is_some() => {}
            "kernel.archive_changed.v1"
                if operation == RecordOperation::Archive && record == id => {}
            "kernel.facet_observed.v1"
                if record == id
                    && payload["key"]
                        .as_str()
                        .is_some_and(|key| args["facets"].get(key).is_some()) => {}
            "kernel.generic_link_added.v1"
            | "kernel.generic_link_note_updated.v1"
            | "kernel.generic_link_removed.v1" => {
                let link = before_links
                    .iter()
                    .chain(post_links.iter())
                    .find(|link| link["id"] == payload["link_id"])
                    .ok_or_else(fail)?;
                if !requested_links
                    .iter()
                    .any(|request| matches_link(link, request))
                {
                    return Err(fail());
                }
            }
            _ => return Err(fail()),
        }
    }
    if receipt["changed"] == false {
        if !effects.is_empty()
            || operation == RecordOperation::Create
            || receipt["act"].is_number()
            || receipt.get("write_receipt").is_some()
        {
            return Err(fail());
        }
    } else {
        if effects.is_empty() || receipt["act"].as_i64() != Some(fact_act) {
            return Err(fail());
        }
        // Archive's native receipt deliberately has no effect reference.
        if operation != RecordOperation::Archive {
            let last = effects.last().ok_or_else(fail)?;
            let reference = receipt.pointer("/write_receipt/event").ok_or_else(fail)?;
            let event_id: Option<String> =
                sqlx::query_scalar("SELECT id FROM main.content_events WHERE seq=?")
                    .bind(last.0)
                    .fetch_optional(&mut *conn)
                    .await?;
            if receipt
                .pointer("/write_receipt/kind")
                .and_then(Value::as_str)
                != Some("kernel_content_event")
                || reference["seq"].as_i64() != Some(last.0)
                || reference["event_id"].as_str() != event_id.as_deref()
                || reference["record_id"] != last.2
                || reference["event_type"] != last.1
            {
                return Err(fail());
            }
        }
    }
    let (typ, kind) = super::super::v1_type_and_kind(
        post.pin.as_ref().map(|p| p.family.as_str()),
        post.pin.as_ref().map(|p| p.version),
        post.primary_type.as_deref(),
        post.kind.as_deref(),
        &post.fields,
    );
    if operation == RecordOperation::Create {
        let created = creation.ok_or_else(fail)?;
        let lifecycle = args["lifecycle"]
            .as_str()
            .or_else(|| (args["type"] == "WorkItem").then_some("open"));
        let mut expected_fields = crate::v2_standard::v1_compat::compat_fields(
            args["type"].as_str().ok_or_else(fail)?,
            args["kind"].as_str().ok_or_else(fail)?,
            args["name"].as_str(),
            args["summary"].as_str(),
            lifecycle,
        );
        if args["type"] == "Document" {
            expected_fields.remove("v1_type");
            expected_fields.remove("v1_kind");
        }
        if before.is_some()
            || typ != args["type"].as_str()
            || kind != args["kind"].as_str()
            || post.fields != expected_fields
            || receipt["type"] != args["type"]
            || receipt["kind"] != args["kind"]
            || receipt["name"] != args["name"]
            || !args["id_nonce"].as_str().is_some_and(|nonce| {
                crate::record_id::verify(
                    &crate::record_id::qualified_principal(actor),
                    "first-party",
                    id,
                    nonce,
                )
            })
            || created.pointer("/origin/record_id_mint/nonce") != args.get("id_nonce")
            || created
                .pointer("/origin/record_id_mint/context")
                .and_then(Value::as_str)
                != Some("first-party")
            || created
                .pointer("/origin/record_id_mint/principal")
                .and_then(Value::as_str)
                != Some(crate::record_id::qualified_principal(actor).as_str())
            || post.effective_body() != args["body"].as_str()
        {
            return Err(fail());
        }
    } else if before.is_none() {
        return Err(fail());
    }
    // Create already checked the complete native effective field set above.
    // In particular a WorkItem lifecycle:null means the native default open;
    // update lifecycle:null still retains its ordinary clearing semantics.
    if operation != RecordOperation::Create {
        for (input, field) in [
            ("name", "title"),
            ("summary", "summary"),
            ("lifecycle", "lifecycle"),
        ] {
            if let Some(expected) = args.get(input) {
                if post.fields.get(field).unwrap_or(&Value::Null)
                    != &crate::structured_values::normalize(expected)
                {
                    return Err(fail());
                }
            }
        }
    }
    if let Some(expected) = args.get("persistence") {
        if post.metadata.persistence != expected.as_str().ok_or_else(fail)? {
            return Err(fail());
        }
    }
    if let Some(expected) = args.get("maturity") {
        if serde_json::to_value(&post.metadata.maturity)? != *expected {
            return Err(fail());
        }
    }
    if let Some(home) = args["home_id"].as_str() {
        let home = if crate::mcp::tools::redirects_root_filing(typ, Some(home)) {
            crate::schema::UNFILED_RECORD_ID
        } else {
            home
        };
        let expected = crate::v1_import::resolve_home_on_connection(conn, actor, home).await?;
        if post.home_id != expected {
            return Err(fail());
        }
    }
    if operation == RecordOperation::Update {
        let before = before.as_ref().ok_or_else(fail)?;
        let body = before.effective_body().unwrap_or("");
        if crate::mcp::tools::lifecycle::whole_body_write_needs_guard(
            args.get("body").is_some() || args.get("body_set").is_some(),
            before.body.as_deref(),
            args["if_body_digest"].as_str(),
            args["if_unmodified_since"].as_str(),
        ) {
            return Err(fail());
        }
        if args["if_body_digest"].as_str().is_some_and(|expected| {
            expected != crate::mcp::tools::lifecycle::body_digest(before.body.as_deref())
        }) {
            return Err(fail());
        }
        if let Some(expected) = args["if_unmodified_since"].as_str() {
            let parse = |v: &str| chrono::DateTime::parse_from_rfc3339(v).map_err(|_| fail());
            if parse(expected)? != parse(&before.updated_at)? {
                return Err(fail());
            }
        }
        let expected = if args.get("body").is_some() || args.get("body_set").is_some() {
            Some(
                args.get("body")
                    .or_else(|| args.get("body_set"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned(),
            )
        } else if let Some(append) = args["body_append"].as_str() {
            Some(format!("{body}{append}"))
        } else if let Some(replacements) = args.get("body_replace") {
            Some(super::replace_body(body, replacements.clone())?)
        } else {
            None
        };
        if expected.is_some_and(|body| post.effective_body().unwrap_or("") != body) {
            return Err(fail());
        }
    }
    if operation == RecordOperation::Archive {
        let expected = args["archived"].as_bool().unwrap_or(true);
        if post.archived != expected || receipt["archived"] != expected {
            return Err(fail());
        }
    }
    for request in requested_links {
        let remove = operation == RecordOperation::LinkRemove;
        let found = post_links.iter().find(|link| matches_link(link, request));
        if remove {
            if found.is_some() {
                return Err(fail());
            }
        } else if found
            .is_none_or(|link| link["note"] != request.get("note").cloned().unwrap_or(Value::Null))
        {
            return Err(fail());
        }
    }
    // Timestamped/facet conflict semantics are not guessed from final values.
    // Keep these originals retained until the native observation proof is added.
    if args["facets"]
        .as_object()
        .is_some_and(|facets| !facets.is_empty())
    {
        return Err(fail());
    }
    Ok(true)
}
impl RecordOperation {
    pub(crate) fn from_catalog(executor: &str, operation: &str) -> Option<Self> {
        match (executor, operation) {
            ("records_write", "create_record") => Some(Self::Create),
            ("records_write", "update_record") => Some(Self::Update),
            ("records_lifecycle", "archive_record") => Some(Self::Archive),
            ("records_write", "manage_links.add") => Some(Self::LinkAdd),
            ("records_write", "manage_links.remove") => Some(Self::LinkRemove),
            _ => None,
        }
    }
    pub(crate) fn executor(self) -> &'static str {
        if self == Self::Archive {
            "records_lifecycle"
        } else {
            "records_write"
        }
    }
    pub(crate) fn catalog_operation(self) -> &'static str {
        match self {
            Self::Create => "create_record",
            Self::Update => "update_record",
            Self::Archive => "archive_record",
            Self::LinkAdd => "manage_links.add",
            Self::LinkRemove => "manage_links.remove",
        }
    }
    pub(crate) fn source_tool(self) -> &'static str {
        match self {
            Self::LinkAdd | Self::LinkRemove => "manage_links",
            _ => self.catalog_operation(),
        }
    }
    pub(crate) fn primary_target(self, args: &Value) -> Option<&str> {
        args.get(if matches!(self, Self::LinkAdd | Self::LinkRemove) {
            "source_id"
        } else {
            "id"
        })
        .and_then(Value::as_str)
    }
    pub(crate) fn targets(self, args: &Value) -> Vec<String> {
        let mut ids = std::collections::BTreeSet::new();
        if let Some(id) = self.primary_target(args) {
            ids.insert(id.to_owned());
        }
        if matches!(self, Self::LinkAdd | Self::LinkRemove) {
            if let Some(id) = args["target_id"].as_str() {
                ids.insert(id.to_owned());
            }
        }
        if self == Self::Update {
            if let Some(links) = args["links"].as_array() {
                for link in links {
                    if let Some(id) = link["target_id"].as_str() {
                        ids.insert(id.to_owned());
                    }
                }
            }
        }
        ids.into_iter().collect()
    }
    pub(crate) fn validate(self, args: &Value) -> Result<()> {
        let object = args
            .as_object()
            .ok_or_else(|| invalid("record write needs an object"))?;
        if args.to_string().len() > 1024 * 1024 {
            return Err(invalid("record write exceeds 1MiB"));
        }
        let key = text(args, "idempotency_key")?;
        if key.trim() != key || key.is_empty() || key.chars().count() > 200 {
            return Err(invalid("record write requires its exact original key"));
        }
        let uuid = |field: &str| -> Result<()> {
            let value = text(args, field)?;
            if !uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value) {
                return Err(invalid("record write requires canonical full UUID targets"));
            }
            Ok(())
        };
        match self {
            Self::Create => {
                if !matches!(args["type"].as_str(), Some("Document" | "WorkItem"))
                    || (args["type"] == "Document" && args["kind"] != "note")
                    || (args["type"] == "WorkItem" && args["kind"] != "task")
                    || object.keys().any(|key| {
                        ![
                            "type",
                            "kind",
                            "name",
                            "body",
                            "summary",
                            "home_id",
                            "lifecycle",
                            "persistence",
                            "maturity",
                            "facets",
                            "reason",
                            "idempotency_key",
                            "response_mode",
                        ]
                        .contains(&key.as_str())
                    })
                    || text(args, "name")?.trim().is_empty()
                    || !args["body"].is_string()
                {
                    return Err(invalid(
                        "record-family creates support native Document/note and WorkItem/task",
                    ));
                }
                uuid("home_id")?;
            }
            Self::Update => {
                super::validate_update_shape(args)?;
                uuid("id")?;
            }
            Self::Archive => {
                if object.keys().any(|key| {
                    !["id", "archived", "reason", "idempotency_key"].contains(&key.as_str())
                }) || args
                    .get("archived")
                    .is_some_and(|v| !v.is_boolean() && !v.is_null())
                {
                    return Err(invalid("unsupported archive/restore shape"));
                }
                uuid("id")?;
            }
            Self::LinkAdd | Self::LinkRemove => {
                let expected = if self == Self::LinkAdd {
                    "add"
                } else {
                    "remove"
                };
                if args["action"] != expected
                    || object.keys().any(|key| {
                        ![
                            "action",
                            "source_id",
                            "target_id",
                            "relationship",
                            "note",
                            "idempotency_key",
                        ]
                        .contains(&key.as_str())
                    })
                {
                    return Err(invalid("unsupported native link mutation shape"));
                }
                uuid("source_id")?;
                uuid("target_id")?;
                text(args, "relationship")?;
            }
        }
        for id in self.targets(args) {
            if !uuid::Uuid::parse_str(&id).is_ok_and(|parsed| parsed.to_string() == id) {
                return Err(invalid("record write requires canonical full UUID targets"));
            }
        }
        Ok(())
    }
}

pub(crate) fn first_party_final_create_enabled() -> bool {
    super::minted_ids_enabled()
}

pub(crate) struct CapturedFirstPartyCreate {
    caller: crate::mcp::Caller,
    source: Value,
    context: FirstPartyCreateContext,
    annotations: crate::store::EventAnnotations,
}
#[derive(Clone, Debug)]
pub(crate) struct FirstPartyCreateContext {
    observed: String,
}
impl FirstPartyCreateContext {
    #[cfg(all(feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
    pub(super) fn for_enrolled_node() -> Result<Self> {
        if !super::minted_ids_enabled() {
            return Err(invalid("hosted minted-id admission is disabled"));
        }
        Ok(Self {
            observed: "first-party".into(),
        })
    }
    /// A fresh execution-context observation for continuation of an already
    /// durable original. The current operation remains the actual read, never
    /// a create dispatch reconstructed from the stored arguments.
    pub(crate) fn observe_current_read(caller: &crate::mcp::Caller) -> Result<Self> {
        let observed = crate::provenance::current_read_mint_context(caller)?;
        if observed != "first-party" || !super::minted_ids_enabled() {
            return Err(invalid(
                "retained create requires a current first-party read context",
            ));
        }
        Ok(Self { observed })
    }
    pub(crate) fn identity(&self) -> ProposalIdentity {
        ProposalIdentity {
            app: None,
            mint_context: Some(self.observed.clone()),
        }
    }
    pub(super) fn observed(&self) -> &str {
        &self.observed
    }
}
impl CapturedFirstPartyCreate {
    pub(crate) fn capture(caller: crate::mcp::Caller, source: Value) -> Result<Self> {
        Self::capture_source(caller, source, false)
    }
    pub(crate) fn capture_record(caller: crate::mcp::Caller, source: Value) -> Result<Self> {
        Self::capture_source(caller, source, true)
    }
    fn capture_source(caller: crate::mcp::Caller, source: Value, family: bool) -> Result<Self> {
        if family {
            RecordOperation::Create.validate(&source)?;
        } else {
            validate_first_party_create_source(&source)?;
        }
        let identity = super::ambient_proposal_identity("create_record", &source)?;
        let observed = crate::provenance::record_mint_context()?;
        if caller.host_asserted_app().is_some()
            || identity.app.is_some()
            || observed != "first-party"
        {
            return Err(invalid(
                "first-party create refuses application or delegation identity",
            ));
        }
        if !super::minted_ids_enabled() {
            return Err(invalid("final record IDs are not enabled"));
        }
        Ok(Self {
            caller,
            source,
            context: FirstPartyCreateContext { observed },
            annotations: crate::store::current_event_annotations(),
        })
    }
    pub(crate) fn caller(&self) -> &crate::mcp::Caller {
        &self.caller
    }
    pub(crate) fn source(&self) -> &Value {
        &self.source
    }
    pub(crate) fn context(&self) -> &FirstPartyCreateContext {
        &self.context
    }
    pub(crate) fn annotations(&self) -> crate::store::EventAnnotations {
        self.annotations.clone()
    }
    /// The journal must call this only after checking the original actor/key
    /// under its existing revision fence. A retry supplies the retained proof.
    pub(crate) fn prepare(&self, actor: &str, retained: Option<&Value>) -> Result<ReplayProposal> {
        let args = if let Some(retained) = retained {
            let mut original = retained.clone();
            let object = original
                .as_object_mut()
                .ok_or_else(|| invalid("retained create object missing"))?;
            object.remove("id");
            object.remove("id_nonce");
            if original != self.source {
                return Err(crate::Error::conflict(
                    "create key is reserved for different original bytes",
                ));
            }
            retained.clone()
        } else {
            use rand::TryRngCore;
            let mut nonce = [0; 32];
            rand::rngs::OsRng
                .try_fill_bytes(&mut nonce)
                .map_err(|_| invalid("record nonce generation unavailable"))?;
            let (id, nonce) = crate::record_id::mint(
                &crate::record_id::qualified_principal(actor),
                &self.context.observed,
                nonce,
            );
            let mut args = self.source.clone();
            args["id"] = id.into();
            args["id_nonce"] = nonce.into();
            args
        };
        if !crate::record_id::verify(
            &crate::record_id::qualified_principal(actor),
            &self.context.observed,
            text(&args, "id")?,
            text(&args, "id_nonce")?,
        ) {
            return Err(invalid("invalid original record id proof"));
        }
        ReplayProposal::from_original(
            "create_record",
            args,
            self.source
                .get("idempotency_key")
                .and_then(Value::as_str)
                .map(str::to_owned),
            &self.context.identity(),
        )
    }
}
/// Page input deliberately excludes host-owned proof fields and all composite
/// create semantics. The ordinary native write still authorizes the home.
pub(crate) fn validate_first_party_create_source(args: &Value) -> Result<()> {
    let object = args
        .as_object()
        .ok_or_else(|| invalid("create requires an object"))?;
    if args.to_string().len() > 1024 * 1024
        || object.keys().any(|key| {
            ![
                "type",
                "kind",
                "name",
                "body",
                "home_id",
                "reason",
                "idempotency_key",
                "response_mode",
            ]
            .contains(&key.as_str())
        })
        || args["type"] != "Document"
        || args["kind"] != "note"
        || text(args, "name")?.trim().is_empty()
        || !args["body"].is_string()
        || !args["reason"].is_string()
        || uuid::Uuid::parse_str(text(args, "home_id")?).is_err()
        || args.get("response_mode").is_some_and(|mode| mode != "full")
    {
        return Err(invalid(
            "only bounded plain-note creates in one explicit home are supported",
        ));
    }
    let home = text(args, "home_id")?;
    if uuid::Uuid::parse_str(home).is_ok_and(|id| id.to_string() != home) {
        return Err(invalid("home must be a canonical full UUID"));
    }
    let key = text(args, "idempotency_key")?;
    if key.trim() != key || key.is_empty() || key.chars().count() > 200 {
        return Err(invalid(
            "create requires its exact original key (1..200 characters)",
        ));
    }
    Ok(())
}

/// Typed placeholder for the minting context the caller supplies alongside
/// the resolved principal. Ignored until the parallel task wires verified
/// minted IDs.
#[derive(Clone, Debug, Default)]
pub(crate) struct PendingMintContext;

/// Caller-supplied authority for a replay: the resolved actual principal and
/// the (currently placeholder) minting context. Neither is re-derived from
/// the proposal's arguments.
#[derive(Clone, Debug)]
pub(crate) struct ReplayCaller {
    /// Resolved principal id (for example `acct:...`).
    pub actor: String,
    /// Minting context; ignored for now.
    pub mint: PendingMintContext,
}

/// The immutable original proposal being replayed: the tool, its arguments,
/// the idempotency key and request fingerprint they were first admitted
/// under, and the original admission identity. The identity comes from the
/// caller (the original journalled call), never from the arguments, and
/// confers no authority. Fields are private so construction goes only
/// through [`ReplayProposal::from_original`]; the `mint_proof` placeholder
/// from #3418 is gone, replaced by the explicit [`ProposalIdentity`] the
/// parallel minted-IDs task wires.
#[derive(Clone, Debug)]
pub(crate) struct ReplayProposal {
    tool: String,
    args: Value,
    idempotency_key: Option<String>,
    request_fingerprint: String,
    identity: ProposalIdentity,
}

impl ReplayProposal {
    /// The proposed tool.
    pub(crate) fn tool(&self) -> &str {
        &self.tool
    }

    /// The proposed arguments.
    pub(crate) fn args(&self) -> &Value {
        &self.args
    }

    /// The proposed idempotency key, if any.
    pub(crate) fn idempotency_key(&self) -> Option<&str> {
        self.idempotency_key.as_deref()
    }

    /// The fingerprint the proposal was journalled under.
    pub(crate) fn request_fingerprint(&self) -> &str {
        &self.request_fingerprint
    }

    /// The original admission identity the fingerprint was computed with.
    pub(crate) fn identity(&self) -> &ProposalIdentity {
        &self.identity
    }

    /// Test-only escape hatch for tampering with the stored fingerprint, to
    /// prove validation catches a proposal that no longer matches its
    /// arguments.
    #[cfg(test)]
    pub(crate) fn with_request_fingerprint(mut self, request_fingerprint: String) -> Self {
        self.request_fingerprint = request_fingerprint;
        self
    }
}

impl ReplayProposal {
    /// Build the immutable original proposal, fingerprinting it under the
    /// caller-supplied identity. Rejects any disagreement between the
    /// idempotency key parameter and the arguments' key: the two must be
    /// absent together or hold the same trimmed value.
    pub(crate) fn from_original(
        tool: &str,
        args: Value,
        idempotency_key: Option<String>,
        identity: &ProposalIdentity,
    ) -> Result<ReplayProposal> {
        let canonical = |key: &Option<String>| {
            key.as_deref()
                .map(str::trim)
                .filter(|key| !key.is_empty())
                .map(str::to_owned)
        };
        let args_key = super::optional_text(&args, "idempotency_key")?
            .map(str::trim)
            .filter(|key| !key.is_empty());
        if canonical(&idempotency_key).as_deref() != args_key {
            return Err(super::invalid(
                "replay proposal idempotency key disagrees with its arguments",
            ));
        }
        let request_fingerprint = proposal_fingerprint(tool, &args, identity)?;
        Ok(ReplayProposal {
            tool: tool.into(),
            args,
            idempotency_key: canonical(&idempotency_key),
            request_fingerprint,
            // An explicit JSON null app is the same unset identity, so the
            // carried and ambient comparisons below cannot disagree on it.
            identity: ProposalIdentity {
                app: identity.app.clone().filter(|app| !app.is_null()),
                mint_context: identity.mint_context.clone(),
            },
        })
    }

    /// Capture at ingress, inside the ORIGINAL authenticated dispatch scope and
    /// before any async detach: selects identity with the same
    /// `ambient_proposal_identity(tool, args)` that `dispatched_fingerprint`
    /// uses, refuses any non-null identity (app or mint context) with a typed
    /// error, then delegates to `from_original`.
    pub(crate) fn from_current_first_party(
        tool: &str,
        args: Value,
        idempotency_key: Option<String>,
    ) -> Result<ReplayProposal> {
        let identity = super::ambient_proposal_identity(tool, &args)?;
        if !identity.is_null() {
            return Err(super::invalid(format!(
                "{NON_FIRST_PARTY_IDENTITY}: first-party ingress refuses a non-null ambient identity"
            )));
        }
        Self::from_original(tool, args, idempotency_key, &identity)
    }
}

/// Local refusal reason when the ambient dispatch identity differs from the
/// proposal's carried identity. Replay runs with no ambient app/dispatch
/// identity scope; a first-party proposal replayed under a later app scope
/// (or vice versa) must fail closed here rather than record an app
/// fingerprint or action under the wrong scope.
pub(crate) const AMBIENT_IDENTITY_MISMATCH: &str = "AmbientIdentityMismatch";

/// Machine code for the first-party ingress refusal: [`ReplayProposal`]'s
/// ingress constructor runs inside the original dispatch scope, so any ambient
/// app claim or mint context means the call is not first-party. Reported as a
/// hard error (via [`super::invalid`], like this module's other proposal hard
/// errors) carrying this code — never by substituting a null identity.
pub(crate) const NON_FIRST_PARTY_IDENTITY: &str = "NonFirstPartyIdentity";

/// The LOCAL outcome of one replay. This is a decision of the replaying node
/// only — never a hosted verdict. `Applied` means the ordinary write path ran
/// and its receipt committed into the caller's transaction (durable only once
/// the caller commits); `LocallyRefused` means nothing ran and only the
/// replay's savepoint was rolled back.
#[derive(Clone, Debug)]
pub(crate) enum ReplayOutcome {
    Applied {
        touched_record_ids: Vec<String>,
        receipt: Value,
    },
    LocallyRefused {
        reason: String,
    },
}

/// A claimed savepoint name for one replay. The name is caller-visible so a
/// dropped (cancelled) replay future can still be cleaned up: dropping the
/// future cannot run the `ROLLBACK TO`/`RELEASE` SQL itself, so the caller
/// must either roll back its outer transaction or call
/// [`ReplaySavepoint::rollback_abandoned`] before reusing the connection.
/// Savepoint names are unique per process; replay itself installs no triggers
/// and leaves no other connection state behind.
#[derive(Debug)]
pub(crate) struct ReplaySavepoint {
    name: String,
    #[cfg(test)]
    cleanup_fault: Option<std::sync::Arc<ReplayCleanupFault>>,
}
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum ReplayCleanupStep {
    Observe,
    RollbackTo,
    Release,
}
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ReplayCleanupFault {
    step: ReplayCleanupStep,
    rollback: AtomicU64,
    release: AtomicU64,
}
#[cfg(test)]
impl ReplayCleanupFault {
    pub(crate) fn new(step: ReplayCleanupStep) -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            step,
            rollback: AtomicU64::new(0),
            release: AtomicU64::new(0),
        })
    }
    pub(crate) fn counts(&self) -> (u64, u64) {
        (
            self.rollback.load(Ordering::SeqCst),
            self.release.load(Ordering::SeqCst),
        )
    }
}

static REPLAY_SAVEPOINT_SEQ: AtomicU64 = AtomicU64::new(1);

impl ReplaySavepoint {
    /// Claim a fresh savepoint name for one replay call.
    pub(crate) fn claim() -> Self {
        Self {
            name: format!(
                "native_replay_{}",
                REPLAY_SAVEPOINT_SEQ.fetch_add(1, Ordering::Relaxed)
            ),
            #[cfg(test)]
            cleanup_fault: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_cleanup_fault(
        mut self,
        fault: Option<std::sync::Arc<ReplayCleanupFault>>,
    ) -> Self {
        self.cleanup_fault = fault;
        self
    }
    /// Only the outer replay error arm owns these two acknowledgements.
    async fn rollback_error(&self, tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
        #[cfg(test)]
        let rollback_name = if let Some(fault) = &self.cleanup_fault {
            fault.rollback.fetch_add(1, Ordering::SeqCst);
            if matches!(fault.step, ReplayCleanupStep::RollbackTo) {
                "missing_replay_cleanup_scope"
            } else {
                &self.name
            }
        } else {
            &self.name
        };
        #[cfg(not(test))]
        let rollback_name = &self.name;
        sqlx::query(&format!("ROLLBACK TO SAVEPOINT {rollback_name}"))
            .execute(&mut **tx)
            .await?;
        #[cfg(test)]
        let release_name = if let Some(fault) = &self.cleanup_fault {
            fault.release.fetch_add(1, Ordering::SeqCst);
            if matches!(fault.step, ReplayCleanupStep::Release) {
                "missing_replay_cleanup_scope"
            } else {
                &self.name
            }
        } else {
            &self.name
        };
        #[cfg(not(test))]
        let release_name = &self.name;
        sqlx::query(&format!("RELEASE {release_name}"))
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// The claimed SQL savepoint name.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Roll back an abandoned (cancelled) replay's savepoint so the outer
    /// transaction is reusable. Call this only for futures that never
    /// returned: after a normal return the savepoint is already released,
    /// and calling this then fails with SQLite's "no such savepoint" error
    /// instead of being a no-op.
    ///
    /// If this cleanup itself fails — including "no such savepoint" when the
    /// future was dropped before opening it — the caller must roll back the
    /// outer transaction instead of reusing it. Only a successful cleanup
    /// proves the connection reusable.
    pub(crate) async fn rollback_abandoned(&self, tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
        rollback_to_savepoint(tx, &self.name).await
    }
}

async fn rollback_to_savepoint(tx: &mut Transaction<'_, Sqlite>, name: &str) -> Result<()> {
    sqlx::query(&format!("ROLLBACK TO SAVEPOINT {name}"))
        .execute(&mut **tx)
        .await?;
    sqlx::query(&format!("RELEASE {name}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Deterministic pause points for cancellation tests. Each hook is one-shot:
/// arming it lets exactly one replay pause there, so a test can drop the
/// future at a precise point — after the mutation with the savepoint still
/// open, or after the release — instead of racing an abort. Thread-local and
/// test-only: a test arms the hook and drives its replay on the same thread
/// with no awaits in between, so concurrent tests can never observe or steal
/// each other's hooks.
#[cfg(test)]
pub(crate) mod cancellation_probe {
    use std::cell::Cell;

    thread_local! {
        static ARMED_BEFORE_RELEASE: Cell<bool> = const { Cell::new(false) };
        static ARMED_AFTER_RELEASE: Cell<bool> = const { Cell::new(false) };
        static REACHED_BEFORE_RELEASE: Cell<bool> = const { Cell::new(false) };
        static REACHED_AFTER_RELEASE: Cell<bool> = const { Cell::new(false) };
    }

    /// Pause the next replay on this thread after its mutation, before it
    /// releases the savepoint. The replay stays there until the test drops
    /// it.
    pub(crate) fn arm_before_release() {
        REACHED_BEFORE_RELEASE.with(|reached| reached.set(false));
        ARMED_BEFORE_RELEASE.with(|armed| armed.set(true));
    }

    /// Pause the next replay on this thread after it releases the savepoint.
    pub(crate) fn arm_after_release() {
        REACHED_AFTER_RELEASE.with(|reached| reached.set(false));
        ARMED_AFTER_RELEASE.with(|armed| armed.set(true));
    }

    pub(crate) fn reached_before_release() -> bool {
        REACHED_BEFORE_RELEASE.with(|reached| reached.get())
    }

    pub(crate) fn reached_after_release() -> bool {
        REACHED_AFTER_RELEASE.with(|reached| reached.get())
    }

    pub(crate) async fn pause_before_release() {
        if ARMED_BEFORE_RELEASE.with(|armed| armed.replace(false)) {
            REACHED_BEFORE_RELEASE.with(|reached| reached.set(true));
            std::future::pending::<()>().await;
        }
    }

    pub(crate) async fn pause_after_release() {
        if ARMED_AFTER_RELEASE.with(|armed| armed.replace(false)) {
            REACHED_AFTER_RELEASE.with(|reached| reached.set(true));
            std::future::pending::<()>().await;
        }
    }
}

/// The single write this replay may run, after the allowlist and liveness
/// checks pass.
enum Eligible {
    CreateNote,
    UpdateBodyAppend {
        id: String,
    },
    AddLink,
    Record {
        operation: RecordOperation,
        id: Option<String>,
    },
}

/// The explicit replay allowlist: plain note `create_record`, `update_record`
/// body append, and `manage_links` add. Anything else refuses without running.
///
/// Presence decides: an explicit null is a mutation on the ordinary path
/// (for example `"maturity": null` clears maturity), so any key outside the
/// permitted set refuses, null or not.
fn check_eligible(tool: &str, args: &Value) -> std::result::Result<Eligible, String> {
    match tool {
        "create_record" => {
            if args.get("type").and_then(Value::as_str) != Some("Document")
                || args.get("kind").and_then(Value::as_str) != Some("note")
            {
                return Err(
                    "only plain Document/note create_record is replayable in a caller-owned transaction"
                        .into(),
                );
            }
            for key in ["id", "target", "access_policy"] {
                if args.get(key).is_some() {
                    return Err(format!("create_record replay refuses non-note field {key}"));
                }
            }
            Ok(Eligible::CreateNote)
        }
        "update_record" => {
            // Exactly one body operation, and it is the append; every other
            // key on the request must be the id, the append, or a guard or
            // envelope the ordinary path treats as read-only.
            const APPEND_ONLY: &[&str] = &[
                "id",
                "body_append",
                "reason",
                "response_mode",
                "idempotency_key",
                "if_body_digest",
                "if_unmodified_since",
                "if_policy_revision",
                "sources",
            ];
            let object = args
                .as_object()
                .ok_or_else(|| "update_record replay needs an object".to_string())?;
            for key in object.keys() {
                if !APPEND_ONLY.contains(&key.as_str()) {
                    return Err(format!(
                        "update_record replay refuses field {key}; only body append replays"
                    ));
                }
            }
            let id = text(args, "id")
                .map_err(|error| error.to_string())?
                .to_owned();
            text(args, "body_append").map_err(|error| error.to_string())?;
            Ok(Eligible::UpdateBodyAppend { id })
        }
        "manage_links" => {
            if args.get("action").and_then(Value::as_str) != Some("add") {
                return Err(
                    "only manage_links add is replayable in a caller-owned transaction".into(),
                );
            }
            Ok(Eligible::AddLink)
        }
        _ => Err(format!(
            "tool {tool} is not replayable in a caller-owned transaction"
        )),
    }
}

#[cfg(all(feature = "v2-kernel-probe", feature = "mcp-executor-prototype"))]
pub(super) async fn admit_enrolled_node_on(
    tx: &mut SqliteConnection,
    actor: &str,
    original: &crate::kernel::original_settlement::Original,
) -> Result<()> {
    let mut args = original.arguments.clone();
    if original.operation == "create_record" {
        let object = args
            .as_object_mut()
            .ok_or_else(|| invalid("create object missing"))?;
        object.remove("id");
        object.remove("id_nonce");
    }
    match original.journal_variant {
        7 => {
            let Eligible::UpdateBodyAppend { id } =
                check_eligible(&original.operation, &args).map_err(invalid)?
            else {
                return Err(invalid("installed append shape required"));
            };
            let current = view(tx, actor, &id).await?;
            if !is_plain_note_on(tx, &current).await? {
                return Err(invalid("installed append requires a visible plain note"));
            }
        }
        8 => validate_first_party_create_source(&args)?,
        9 => RecordOperation::from_catalog(&original.catalog_executor, &original.catalog_operation)
            .filter(|operation| operation.source_tool() == original.operation)
            .ok_or_else(|| invalid("installed write operation is unavailable"))?
            .validate(&args)?,
        _ => return Err(invalid("installed write profile is unavailable")),
    }
    Ok(())
}

/// Whether the visible record is a plain note under either documented note
/// family: the resolved public type/kind is `Document`/`note`, whether the
/// record rides `document@4` or the v1 compat carrier. Anything untyped or
/// of another type fails closed.
async fn is_plain_note_on(
    tx: &mut SqliteConnection,
    previous: &crate::kernel::KernelRecordView,
) -> Result<bool> {
    let primary_type: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(&previous.id)
            .fetch_one(&mut *tx)
            .await?;
    let (typ, kind) = crate::mcp::kernel_v2::v1_type_and_kind(
        previous.family.as_deref(),
        previous.pin.as_ref().map(|pin| pin.version),
        primary_type.as_deref(),
        previous.kind.as_deref(),
        &previous.fields,
    );
    Ok(typ == Some("Document") && kind == Some("note"))
}

/// References to the actual working owner, not a detached profile or verdict.
/// Every probe revalidates them against its borrowed root transaction.
#[cfg(feature = "v2-kernel-probe")]
#[derive(Clone, Copy)]
pub(crate) struct WorkingReplayOwner<'a> {
    pub(crate) schema: &'a crate::standby::kernel_v2::WorkingKernelSchema,
    pub(crate) collector: &'a crate::kernel::working_undo::Collector,
}
#[cfg(not(feature = "v2-kernel-probe"))]
#[derive(Clone, Copy)]
pub(crate) struct WorkingReplayOwner<'a> {
    _unavailable: std::convert::Infallible,
    _lifetime: std::marker::PhantomData<&'a ()>,
}
#[cfg(feature = "v2-kernel-probe")]
impl WorkingReplayOwner<'_> {
    pub(crate) async fn outcomes<'c, 'conn>(
        &'c self,
        tx: &'c mut Transaction<'conn, Sqlite>,
    ) -> Result<crate::kernel::original_settlement::outcome_profile::VerifiedOutcomeSnapshot<'c>>
    {
        crate::kernel::original_settlement::outcome_profile::verified_working_outcomes_on(
            self.schema,
            tx,
            self.collector,
        )
        .await
        .map_err(|error| crate::Error::engine(error.code()))
    }
}

/// What the idempotency-key probe found. Mirrors the ordinary receipt
/// lookup, which runs before the live-write refusal: an exact retry returns
/// the stored receipt without another mutation, while a mismatch is the
/// ordinary keyed conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyedRetry {
    /// No key, or no stored outcome under it: the write would mutate.
    Absent,
    /// Same key and same request: replay returns the stored receipt.
    Exact,
    /// Same key, different request: the ordinary conflict.
    Mismatch,
}

/// Probe the stored keyed outcome for this principal, tool and key, and
/// compare its request fingerprint with the proposal's. Read-only: the
/// ordinary path re-does the lookup with its authorization and replay
/// bookkeeping when the write itself runs.
async fn keyed_retry_probe(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    tool: &str,
    key: Option<&str>,
    request_fingerprint: &str,
    owner: Option<WorkingReplayOwner<'_>>,
) -> Result<KeyedRetry> {
    #[cfg(feature = "v2-kernel-probe")]
    use crate::kernel::original_settlement::{
        outcome_profile::{self, OutcomeLookup},
        KeyedOutcome,
    };
    let Some(key) = key.filter(|key| !key.is_empty()) else {
        return Ok(KeyedRetry::Absent);
    };
    #[cfg(not(feature = "v2-kernel-probe"))]
    {
        let _ = owner;
        let old: Option<(String,String)> = sqlx::query_as("SELECT request_json,receipt_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation=? AND operation_key=?")
            .bind(actor).bind(tool).bind(key).fetch_optional(&mut **tx).await?;
        let Some((request, _)) = old else {
            return Ok(KeyedRetry::Absent);
        };
        return Ok(
            if super::stored_fingerprint(tool, serde_json::from_str(&request)?)?
                == request_fingerprint
            {
                KeyedRetry::Exact
            } else {
                KeyedRetry::Mismatch
            },
        );
    }
    #[cfg(feature = "v2-kernel-probe")]
    {
        let mut snapshot = match owner.as_ref() {
            Some(owner) => owner.outcomes(tx).await?,
            None => outcome_profile::verified_outcomes_on(tx)
                .await
                .map_err(|error| crate::Error::engine(error.code()))?,
        };
        let outcome = snapshot
            .lookup(actor, tool, key)
            .await
            .map_err(|error| crate::Error::engine(error.code()))?;
        if let Some(conflict) = outcome.terminal_conflict() {
            // Only the outer replay wrapper owns rollback/release. The capability
            // and borrowed result drop before that wrapper gets the root back.
            return Err(crate::Error::OriginalConflict(Box::new(conflict)));
        }
        let request = match outcome {
            OutcomeLookup::Legacy(None) | OutcomeLookup::Typed(KeyedOutcome::Absent) => {
                return Ok(KeyedRetry::Absent)
            }
            OutcomeLookup::Legacy(Some((request, _))) => request,
            OutcomeLookup::Typed(KeyedOutcome::Accepted { request, .. }) => request,
            OutcomeLookup::Typed(KeyedOutcome::Terminal { .. }) => {
                unreachable!("terminal handled above")
            }
        };
        if super::stored_fingerprint(tool, serde_json::from_str(request)?)? != request_fingerprint {
            return Ok(KeyedRetry::Mismatch);
        }
        Ok(KeyedRetry::Exact)
    }
}

fn touched_ids(_tool: &str, args: &Value, receipt: &Value) -> Vec<String> {
    let mut ids = Vec::new();
    for key in ["id", "source_id", "target_id"] {
        if let Some(id) = receipt.get(key).and_then(Value::as_str) {
            if !ids.contains(&id.to_owned()) {
                ids.push(id.to_owned());
            }
        }
    }
    if ids.is_empty() {
        if let Some(id) = args.get("id").and_then(Value::as_str) {
            ids.push(id.to_owned());
        }
    }
    ids
}

/// Replay one allowlisted write inside the caller's transaction.
///
/// Runs the same validation and receipt semantics as an ordinary write
/// ([`execute_transaction`] with no live body context) inside its OWN
/// savepoint (`savepoint`, claimed by the caller) on `tx`. On success the
/// savepoint is released and the receipt stays in the outer transaction; on
/// any refusal or write error only the savepoint rolls back and the outcome
/// reports [`ReplayOutcome::LocallyRefused`].
///
/// This never begins, commits or rolls back the outer transaction, never
/// opens a write transaction of its own, installs no triggers, and never
/// wakes realtime — the caller wakes realtime itself after its outer commit.
///
/// Refusals that never bypass the owned write path: unknown tools, shapes
/// outside the allowlist, invisible/missing/non-note targets, proposals
/// carrying a non-null original identity (see below), and body appends on
/// records with an open live body session (those need live-body ownership
/// and their own `KernelTransaction`; see `execute_update_owned`). Like the
/// ordinary path, the stored-receipt lookup runs before the live-room
/// refusal: an authorized same-key, same-request retry returns the stored
/// receipt without another body mutation even while a room is open.
/// A replayed proposal is immutable, so a key or fingerprint that disagrees
/// with its arguments is corruption: a hard error, never a local refusal.
/// Only savepoint-mechanics failures join it as hard errors.
///
/// Identity boundary: [`ReplayProposal::from_original`] fingerprints the
/// proposal under the caller-supplied original identity, and replay
/// revalidates against that same carried identity — never the ambient
/// dispatch. The supported caller boundary is no ambient app/dispatch
/// identity scope, which is how the working-copy manager calls it; replay
/// fails closed with [`AMBIENT_IDENTITY_MISMATCH`] when the ambient identity
/// [`super::ambient_proposal_identity`] would select differs from the
/// proposal's carried identity. The ordinary write path still runs under
/// the caller's ambient scope with its authority rechecked, and it still
/// builds its receipt request from that scope. Until the admission wiring
/// lands that can carry a non-null identity through the receipt path, any
/// proposal whose identity is non-null (app or mint context) fails closed
/// here with a local refusal. The guarantee is: the same outcome or a
/// fail-closed refusal, never a different receipt or action identity.
pub(crate) async fn replay_write_in_transaction(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    caller: &ReplayCaller,
    proposal: &ReplayProposal,
    savepoint: &ReplaySavepoint,
) -> Result<ReplayOutcome> {
    replay_write_with_context(db, tx, caller, proposal, savepoint, (None, None, None)).await
}
pub(crate) async fn replay_captured_create_in_transaction(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    caller: &ReplayCaller,
    proposal: &ReplayProposal,
    savepoint: &ReplaySavepoint,
    captured: &FirstPartyCreateContext,
) -> Result<ReplayOutcome> {
    if let Some(refusal) = verify_create_proof(caller, proposal, captured)? {
        return Ok(refusal);
    }
    replay_write_with_context(
        db,
        tx,
        caller,
        proposal,
        savepoint,
        (Some(captured), None, None),
    )
    .await
}
fn verify_create_proof(
    caller: &ReplayCaller,
    proposal: &ReplayProposal,
    captured: &FirstPartyCreateContext,
) -> Result<Option<ReplayOutcome>> {
    if proposal.tool() != "create_record" || proposal.identity() != &captured.identity() {
        return Err(invalid("captured create identity changed"));
    }
    if !proposal
        .args()
        .get("id")
        .and_then(Value::as_str)
        .zip(proposal.args().get("id_nonce").and_then(Value::as_str))
        .is_some_and(|(id, nonce)| {
            crate::record_id::verify(
                &crate::record_id::qualified_principal(&caller.actor),
                captured.observed(),
                id,
                nonce,
            )
        })
    {
        return Ok(Some(ReplayOutcome::LocallyRefused {
            reason: "invalid record id proof".into(),
        }));
    }
    Ok(None)
}
pub(crate) async fn replay_record_in_transaction(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    caller: &ReplayCaller,
    proposal: &ReplayProposal,
    savepoint: &ReplaySavepoint,
    operation: RecordOperation,
    captured: Option<&FirstPartyCreateContext>,
) -> Result<ReplayOutcome> {
    if proposal.tool() != operation.source_tool()
        || (operation == RecordOperation::Create) != captured.is_some()
    {
        return Err(invalid("record-family operation/provider context mismatch"));
    }
    if let Some(context) = captured {
        if let Some(refusal) = verify_create_proof(caller, proposal, context)? {
            return Ok(refusal);
        }
    }
    replay_write_with_context(
        db,
        tx,
        caller,
        proposal,
        savepoint,
        (captured, Some(operation), None),
    )
    .await
}

/// Actual working owner path; uses the same ordinary handlers and cleanup.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn replay_working_in_transaction(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    caller: &ReplayCaller,
    proposal: &ReplayProposal,
    savepoint: &ReplaySavepoint,
    context: (
        Option<RecordOperation>,
        Option<&FirstPartyCreateContext>,
        WorkingReplayOwner<'_>,
    ),
) -> Result<ReplayOutcome> {
    let (operation, captured, owner) = context;
    if operation.is_some_and(|operation| operation.source_tool() != proposal.tool())
        || (proposal.tool() == "create_record") != captured.is_some()
    {
        return Err(invalid("working operation/provider context mismatch"));
    }
    if let Some(captured) = captured {
        if let Some(refusal) = verify_create_proof(caller, proposal, captured)? {
            return Ok(refusal);
        }
    }
    replay_write_with_context(
        db,
        tx,
        caller,
        proposal,
        savepoint,
        (captured, operation, Some(owner)),
    )
    .await
}
async fn replay_write_with_context(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    caller: &ReplayCaller,
    proposal: &ReplayProposal,
    savepoint: &ReplaySavepoint,
    context: (
        Option<&FirstPartyCreateContext>,
        Option<RecordOperation>,
        Option<WorkingReplayOwner<'_>>,
    ),
) -> Result<ReplayOutcome> {
    let (captured, family, owner) = context;
    let _ = &caller.mint;
    // The proposal carries the key, fingerprint and identity explicitly; the
    // first two must agree with the arguments rather than being re-derived
    // from them. Disagreement is corruption, not a user-facing refusal: hard
    // errors below.
    let canonical_key = |key: Option<&str>| {
        key.map(str::trim)
            .filter(|key| !key.is_empty())
            .map(str::to_owned)
    };
    let args_key = optional_text(proposal.args(), "idempotency_key")?
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .map(str::to_owned);
    if canonical_key(proposal.idempotency_key()) != args_key {
        return Err(invalid(
            "replay proposal idempotency key disagrees with its arguments",
        ));
    }
    let expected = proposal_fingerprint(proposal.tool(), proposal.args(), proposal.identity())?;
    if expected != proposal.request_fingerprint() {
        return Err(invalid("replay proposal fingerprint mismatch"));
    }
    if captured.is_none() && !proposal.identity().is_null() {
        return Ok(ReplayOutcome::LocallyRefused {
            reason: "replay proposal carries a non-null original identity; replay waits for the admission wiring"
                .into(),
        });
    }
    // Removing an ambient app scope would run the write with broader
    // (first-party) authority than the current caller has, so a scope that
    // does not match the carried identity fails closed instead. No replay
    // savepoint is open yet — the caller-owned outer transaction was
    // supplied open — so no cleanup is needed.
    let ambient_matches = if captured.is_some() {
        crate::kernel::app_installs::dispatched_identity().is_none_or(|app| app.is_null())
    } else {
        super::ambient_proposal_identity(proposal.tool(), proposal.args())? == *proposal.identity()
    };
    if !ambient_matches {
        return Ok(ReplayOutcome::LocallyRefused {
            reason: format!(
                "{AMBIENT_IDENTITY_MISMATCH}: replay runs with no ambient app/dispatch identity scope"
            ),
        });
    }
    // Shape first: nothing has touched the transaction yet, so a refusal
    // needs no cleanup at all.
    let eligible = match if let Some(operation) = family {
        let mut source = proposal.args().clone();
        if operation == RecordOperation::Create {
            let object = source
                .as_object_mut()
                .ok_or_else(|| invalid("create object missing"))?;
            object.remove("id");
            object.remove("id_nonce");
        }
        operation
            .validate(&source)
            .map(|()| Eligible::Record {
                operation,
                id: operation.primary_target(proposal.args()).map(str::to_owned),
            })
            .map_err(|e| e.to_string())
    } else if captured.is_some() {
        let mut source = proposal.args().clone();
        if let Some(object) = source.as_object_mut() {
            object.remove("id");
            object.remove("id_nonce");
        }
        validate_first_party_create_source(&source)
            .map(|()| Eligible::CreateNote)
            .map_err(|e| e.to_string())
    } else {
        check_eligible(proposal.tool(), proposal.args())
    } {
        Ok(eligible) => eligible,
        Err(reason) => return Ok(ReplayOutcome::LocallyRefused { reason }),
    };
    sqlx::query(&format!("SAVEPOINT {}", savepoint.name()))
        .execute(&mut **tx)
        .await?;
    // Every failure past the savepoint unwinds it before surfacing, so the
    // caller never inherits a half-open replay: refusals roll back and report
    // locally inside, unexpected errors roll back here.
    match replay_in_savepoint(
        db,
        tx,
        &caller.actor,
        proposal,
        &eligible,
        savepoint.name(),
        (captured, owner),
    )
    .await
    {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            savepoint.rollback_error(tx).await?;
            Err(error)
        }
    }
}

/// The savepoint body of [`replay_write_in_transaction`]: update-only gates
/// (visibility, then type, then live room) followed by the ordinary write.
/// Local refusals roll back just this savepoint; unexpected errors propagate
/// to the caller, which unwinds the savepoint before surfacing them.
async fn replay_in_savepoint(
    db: &Db,
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    proposal: &ReplayProposal,
    eligible: &Eligible,
    savepoint: &str,
    context: (
        Option<&FirstPartyCreateContext>,
        Option<WorkingReplayOwner<'_>>,
    ),
) -> Result<ReplayOutcome> {
    let (captured, owner) = context;
    if let Eligible::Record { operation, id } = eligible {
        if *operation != RecordOperation::Create {
            let id = id
                .as_deref()
                .ok_or_else(|| invalid("record-family target missing"))?;
            if view(tx, actor, id).await.is_err() {
                rollback_to_savepoint(tx, savepoint).await?;
                return Ok(ReplayOutcome::LocallyRefused {
                    reason: crate::kernel::HIDDEN_OR_MISSING.into(),
                });
            }
            let retry = keyed_retry_probe(
                tx,
                actor,
                proposal.tool(),
                proposal.idempotency_key(),
                proposal.request_fingerprint(),
                owner,
            )
            .await?;
            // General record replay does not acquire a live/coedit body owner.
            // Keep the existing refusal, including for move/archive/link edits,
            // while exact receipts remain retrievable without another effect.
            if retry == KeyedRetry::Absent && crate::coedit::live::record_has_open_live_room(db, id)
            {
                rollback_to_savepoint(tx, savepoint).await?;
                return Ok(ReplayOutcome::LocallyRefused {reason:"record has an open live body session; record-family replay refuses without its owner".into()});
            }
        }
    }
    if let Eligible::UpdateBodyAppend { id } = eligible {
        // Oracle-safe order: visibility, then type, then live room.
        // Visibility comes first so a hidden target with an open room
        // reports exactly what a missing target reports.
        let previous = match view(tx, actor, id).await {
            Ok(previous) => previous,
            Err(_) => {
                rollback_to_savepoint(tx, savepoint).await?;
                return Ok(ReplayOutcome::LocallyRefused {
                    reason: crate::kernel::HIDDEN_OR_MISSING.into(),
                });
            }
        };
        if !is_plain_note_on(tx, &previous).await? {
            rollback_to_savepoint(tx, savepoint).await?;
            return Ok(ReplayOutcome::LocallyRefused {
                reason: format!(
                    "update_record replay refuses non-note target {id}; only plain note bodies append"
                ),
            });
        }
        // The ordinary receipt lookup runs before its live-write refusal, so
        // the probe does too: an exact keyed retry returns the stored receipt
        // without another mutation even while a room is open; only a write
        // that would mutate is fenced by live-body ownership.
        let key = optional_text(proposal.args(), "idempotency_key")?
            .map(str::trim)
            .filter(|key| !key.is_empty());
        let retry = keyed_retry_probe(
            tx,
            actor,
            proposal.tool(),
            key,
            proposal.request_fingerprint(),
            owner,
        )
        .await?;
        if retry == KeyedRetry::Absent && crate::coedit::live::record_has_open_live_room(db, id) {
            rollback_to_savepoint(tx, savepoint).await?;
            return Ok(ReplayOutcome::LocallyRefused {
                reason: format!(
                    "record {id} has an open live body session; replay refuses rather than bypassing live-body ownership"
                ),
            });
        }
    }
    let executed = if let Some(captured) = captured {
        super::execute_captured_create_transaction(db, tx, actor, proposal.args().clone(), captured)
            .await
    } else {
        execute_transaction(
            db,
            tx,
            actor,
            proposal.tool(),
            proposal.args().clone(),
            None,
        )
        .await
    };
    match executed {
        Ok(receipt) => {
            let touched_record_ids = touched_ids(proposal.tool(), proposal.args(), &receipt);
            #[cfg(test)]
            cancellation_probe::pause_before_release().await;
            sqlx::query(&format!("RELEASE {savepoint}"))
                .execute(&mut **tx)
                .await?;
            #[cfg(test)]
            cancellation_probe::pause_after_release().await;
            Ok(ReplayOutcome::Applied {
                touched_record_ids,
                receipt,
            })
        }
        Err(error @ crate::Error::OriginalConflict(_)) => Err(error),
        Err(error) => {
            rollback_to_savepoint(tx, savepoint).await?;
            Ok(ReplayOutcome::LocallyRefused {
                reason: error.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coedit::live::OpenRequest;
    use crate::coedit::{live::kernel_writes, PeerKind};
    use crate::mcp::kernel_v2::policy_tests::{fixture, Fixture};
    use crate::mcp::registry::Caller;
    use crate::realtime::RealtimeHub;
    use crate::standby::delta_transport::{
        AuthorityActHttpClient, AuthorityActTransport, AuthorityCallFuture,
    };
    use crate::standby::kernel_v2_delta::TrustedKernelDelta;
    use serde_json::json;
    use std::sync::Arc;

    struct Hosted(Db);
    impl AuthorityActHttpClient for Hosted {
        fn call(&self, _endpoint: String, _bearer: String, body: Value) -> AuthorityCallFuture {
            let db = self.0.clone();
            Box::pin(async move {
                let args = &body["params"]["arguments"];
                let value = if args["operation"] == "authority_act_head" {
                    serde_json::to_value(
                        crate::standby::delta_transport::observe_authority_act_head(&db, "route-1")
                            .await?,
                    )?
                } else {
                    serde_json::to_value(
                        crate::standby::delta_transport::observe_authority_act_delta_with_inventory(
                            &db,
                            "route-1",
                            args["arguments"]["from_exclusive_act"].as_i64().unwrap(),
                            Some(&serde_json::from_value::<Vec<String>>(
                                args["arguments"]["blob_inventory"].clone(),
                            )?),
                        )
                        .await?,
                    )?
                };
                Ok(serde_json::to_vec(
                    &json!({"jsonrpc":"2.0","id":body["id"],"result":{"isError":false,"content":[],"structuredContent":value}}),
                )?)
            })
        }
    }

    #[tokio::test]
    async fn record_materialization_binds_minted_create_and_historical_body_cas() {
        super::super::MINTED_IDS_TEST.scope(true, async {
            let f=fixture(false).await;
            let source=json!({"type":"WorkItem","kind":"task","name":"Accepted native task","lifecycle":null,"summary":"accepted summary","body":"accepted create body","home_id":f.folder,"persistence":"enduring","reason":"Family create materialization","idempotency_key":"family-proof-create"});
            let caller=caller(&f);
            let dispatch=crate::provenance::ProvenanceDispatch::from_caller(&caller,"create_record",&source,None);
            let (captured,)=dispatch.scope(async {(CapturedFirstPartyCreate::capture_record(caller.clone(),source).unwrap(),)}).await;
            let proposal=captured.prepare(&f.owner_principal,None).unwrap();
            let mut tx=crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let result=replay_record_in_transaction(&f.db,&mut tx,&caller_of(&f),&proposal,&ReplaySavepoint::claim(),RecordOperation::Create,Some(captured.context())).await.unwrap();
            let ReplayOutcome::Applied{receipt,..}=result else {panic!("native create refused: {result:?}")};
            assert_eq!(proposal.args().get("lifecycle"),Some(&Value::Null),"retain explicit original null bytes");
            assert_eq!(receipt["lifecycle"],"open","native WorkItem creation applies its default");
            let (seq,act):(i64,i64)=sqlx::query_as("SELECT seq,act FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1").bind(crate::kernel::mcp_write_receipts::STREAM).bind(crate::kernel::mcp_write_receipts::EVENT).fetch_one(&mut *tx).await.unwrap();
            assert!(record_materialized_on(&mut tx,&f.owner_principal,RecordOperation::Create,proposal.args(),&receipt,seq,act).await.unwrap());
            let mut wrong=proposal.args().clone();wrong["id_nonce"]=json!("different proof");
            assert!(record_materialized_on(&mut tx,&f.owner_principal,RecordOperation::Create,&wrong,&receipt,seq,act).await.is_err());
            f.db.commit_kernel_content(tx).await.unwrap();
            let edit=json!({"id":proposal.args()["id"],"body_set":"a later accepted body","if_body_digest":receipt["body_digest"],"reason":"Native guarded replacement","idempotency_key":"family-proof-body-cas"});
            let edit=ReplayProposal::from_original("update_record",edit,Some("family-proof-body-cas".into()),&Default::default()).unwrap();
            let mut tx=crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let result=replay_record_in_transaction(&f.db,&mut tx,&caller_of(&f),&edit,&ReplaySavepoint::claim(),RecordOperation::Update,None).await.unwrap();
            let ReplayOutcome::Applied{receipt:edited,..}=result else {panic!("native edit refused: {result:?}")};
            let (edit_seq,edit_act):(i64,i64)=sqlx::query_as("SELECT seq,act FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1").bind(crate::kernel::mcp_write_receipts::STREAM).bind(crate::kernel::mcp_write_receipts::EVENT).fetch_one(&mut *tx).await.unwrap();
            assert!(record_materialized_on(&mut tx,&f.owner_principal,RecordOperation::Update,edit.args(),&edited,edit_seq,edit_act).await.unwrap());
            let mut stale=edit.args().clone();stale["if_body_digest"]=json!("wrong basis");
            assert!(record_materialized_on(&mut tx,&f.owner_principal,RecordOperation::Update,&stale,&edited,edit_seq,edit_act).await.is_err());
            // A later accepted edit does not make the original creation fail
            // against the CURRENT projection or pass with its later body.
            assert!(record_materialized_on(&mut tx,&f.owner_principal,RecordOperation::Create,proposal.args(),&receipt,seq,act).await.unwrap());
            let mut future=proposal.args().clone();future["body"]=json!("a later accepted body");
            assert!(record_materialized_on(&mut tx,&f.owner_principal,RecordOperation::Create,&future,&receipt,seq,act).await.is_err());
            tx.rollback().await.unwrap();
            f.db.close().await;
        }).await;
    }

    /// An empty trusted delta cut at the database's own head: folding it is a
    /// no-op that still exercises the whole fold and certification path.
    async fn empty_delta_for(db: &Db) -> TrustedKernelDelta {
        let head = crate::standby::delta_transport::observe_authority_act_head(db, "route-1")
            .await
            .unwrap();
        let origin = head.head().origin_database_id().to_owned();
        let from = head.head().head_act();
        let transport = AuthorityActTransport::with_client(
            "https://fixture.example",
            "route-1",
            &origin,
            "test-token",
            Arc::new(Hosted(db.clone())),
        )
        .unwrap();
        transport.head().await.unwrap();
        transport.kernel_delta(from, &[]).await.unwrap()
    }

    fn caller_of(fixture: &Fixture) -> ReplayCaller {
        ReplayCaller {
            actor: fixture.owner_principal.clone(),
            mint: PendingMintContext,
        }
    }

    fn caller(fixture: &Fixture) -> Caller {
        Caller::authenticated(fixture.owner.clone())
    }

    #[tokio::test]
    async fn captured_first_party_create_reuses_final_proof_and_native_receipt_without_ambient_dispatch(
    ) {
        super::super::MINTED_IDS_TEST.scope(true,async {
            let f=fixture(false).await;
            let source=json!({"type":"Document","kind":"note","name":"Final ID note","body":"exact retained body","home_id":f.folder,"reason":"provider create proof","idempotency_key":"final-create-original"});
            let original_caller=caller(&f);
            let dispatch=crate::provenance::ProvenanceDispatch::from_caller(&original_caller,"create_record",&source,None);
            let (captured,)=dispatch.scope(async { (CapturedFirstPartyCreate::capture(original_caller.clone(),source.clone()).unwrap(),) }).await;
            let proposal=captured.prepare(&f.owner_principal,None).unwrap();
            let retry=captured.prepare(&f.owner_principal,Some(proposal.args())).unwrap();
            assert_eq!(proposal.args(),retry.args());
            assert_eq!(proposal.request_fingerprint(),retry.request_fingerprint());
            assert!(crate::record_id::verify(&crate::record_id::qualified_principal(&f.owner_principal),"first-party",proposal.args()["id"].as_str().unwrap(),proposal.args()["id_nonce"].as_str().unwrap()));
            let mut changed=source.clone();changed["body"]=json!("different original bytes");
            let other_dispatch=crate::provenance::ProvenanceDispatch::from_caller(&original_caller,"create_record",&changed,None);
            let changed=other_dispatch.scope(async {CapturedFirstPartyCreate::capture(original_caller.clone(),changed).unwrap()}).await;
            assert!(changed.prepare(&f.owner_principal,Some(proposal.args())).is_err());
            let mut wrong=proposal.args().clone();wrong["id_nonce"]=json!("wrong proof");
            assert!(captured.prepare(&f.owner_principal,Some(&wrong)).is_err());
            assert!(captured.prepare("different-author",Some(proposal.args())).is_err());
            assert!(CapturedFirstPartyCreate::capture(original_caller.clone(),source.clone()).is_err(),"missing trusted dispatch cannot become first-party");
            let app_caller=original_caller.clone().with_host_asserted_app(crate::mcp::app_attribution::AppAttribution::new("fixture.app","1","installation-create").unwrap());
            let app_dispatch=crate::provenance::ProvenanceDispatch::from_caller(&app_caller,"create_record",&source,None);
            assert!(app_dispatch.scope(async {CapturedFirstPartyCreate::capture(app_caller,source.clone())}).await.is_err());
            let mut tx=crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let replay_caller=caller_of(&f);
            let mut bad_args=proposal.args().clone();bad_args["id_nonce"]=json!("untrusted nonce");
            let bad=ReplayProposal::from_original("create_record",bad_args,proposal.idempotency_key().map(str::to_owned),&captured.context().identity()).unwrap();
            let refused=replay_captured_create_in_transaction(&f.db,&mut tx,&replay_caller,&bad,&ReplaySavepoint::claim(),captured.context()).await.unwrap();
            assert!(matches!(refused,ReplayOutcome::LocallyRefused { ref reason } if reason.contains("invalid record id proof")),"{refused:?}");
            let first=replay_captured_create_in_transaction(&f.db,&mut tx,&replay_caller,&proposal,&ReplaySavepoint::claim(),captured.context()).await.unwrap();
            let id=applied_id(first);
            let before:i64=sqlx::query_scalar("SELECT count(*) FROM main.content_events").fetch_one(&mut *tx).await.unwrap();
            let replayed=replay_captured_create_in_transaction(&f.db,&mut tx,&replay_caller,&retry,&ReplaySavepoint::claim(),captured.context()).await.unwrap();
            assert_eq!(applied_id(replayed),id);
            let after:i64=sqlx::query_scalar("SELECT count(*) FROM main.content_events").fetch_one(&mut *tx).await.unwrap();
            assert_eq!(before,after,"exact retry authors no second event");
            let request:String=sqlx::query_scalar("SELECT request_json FROM main.kernel_mcp_write_receipts WHERE principal_id=? AND operation='create_record' AND operation_key=?").bind(&f.owner_principal).bind("final-create-original").fetch_one(&mut *tx).await.unwrap();
            assert_eq!(request,proposal.request_fingerprint());
            let body:String=sqlx::query_scalar("SELECT body FROM main.kernel_record_bodies WHERE record_id=?").bind(&id).fetch_one(&mut *tx).await.unwrap();
            assert_eq!(body,"exact retained body");
            tx.rollback().await.unwrap();f.db.close().await;
        }).await;
    }

    #[tokio::test]
    async fn retained_create_observes_current_read_without_remint_or_origin_substitution() {
        super::super::MINTED_IDS_TEST.scope(true,async {
            let f=fixture(false).await;
            let owner=caller(&f);
            let member=Caller::authenticated(f.member.clone());
            assert!(crate::kernel::read_record_as(&f.db,&f.owner_principal,&f.shared).await.unwrap().is_some());
            assert!(crate::kernel::read_record_as(&f.db,&f.member_principal,&f.shared).await.unwrap().is_some());
            let source=json!({"type":"Document","kind":"note","name":"Retained restart note","body":"original restart body","home_id":f.folder,"reason":"Observed-context continuation proof","idempotency_key":"observed-restart-create"});
            let original_scope=crate::provenance::ProvenanceDispatch::from_caller(&owner,"create_record",&source,None);
            let (original,)=original_scope.scope(async {(CapturedFirstPartyCreate::capture(owner.clone(),source.clone()).unwrap(),)}).await;
            let proposal=original.prepare(&f.owner_principal,None).unwrap();
            let saved_args=proposal.args().clone();
            let saved_fp=proposal.request_fingerprint().to_owned();
            assert!(FirstPartyCreateContext::observe_current_read(&owner).is_err());
            assert!(original_scope.scope(async {FirstPartyCreateContext::observe_current_read(&owner)}).await.is_err(),"a create scope is not a current read");
            let mut tx=crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let replay_caller=caller_of(&f);
            let mut expected_events=None;
            for (op,args) in [
                ("get_record",json!({"ids":[proposal.args()["id"]]})),
                ("search",json!({"query":"Retained restart"})),
                ("query_record",json!({"steps":[{"step":"filter","types":["Document"],"kinds":["note"]}]})),
            ] {
                let read_scope=crate::provenance::ProvenanceDispatch::from_caller(&owner,op,&args,Some("new read intent is not original decoration"));
                let (observed,)=read_scope.scope(async {(FirstPartyCreateContext::observe_current_read(&owner).unwrap(),)}).await;
                assert_eq!(observed.identity(),proposal.identity().clone());
                assert!(read_scope.scope(async {FirstPartyCreateContext::observe_current_read(&member)}).await.is_err(),"caller must match the actual observed dispatch");
                let result=replay_captured_create_in_transaction(&f.db,&mut tx,&replay_caller,&proposal,&ReplaySavepoint::claim(),&observed).await.unwrap();
                assert_eq!(applied_id(result),saved_args["id"]);
                let events:i64=sqlx::query_scalar("SELECT count(*) FROM main.content_events").fetch_one(&mut *tx).await.unwrap();
                if let Some(before)=expected_events {assert_eq!(events,before,"fresh read context cannot duplicate an existing keyed effect");} else {expected_events=Some(events);}
                assert_eq!(proposal.args(),&saved_args);
                assert_eq!(proposal.request_fingerprint(),saved_fp);
            }
            let member_read=crate::provenance::ProvenanceDispatch::from_caller(&member,"get_record",&json!({"ids":[f.shared]}),None);
            let (observed,)=member_read.scope(async {(FirstPartyCreateContext::observe_current_read(&member).unwrap(),)}).await;
            let wrong_actor=ReplayCaller{actor:f.member_principal.clone(),mint:Default::default()};
            assert!(matches!(replay_captured_create_in_transaction(&f.db,&mut tx,&wrong_actor,&proposal,&ReplaySavepoint::claim(),&observed).await.unwrap(),ReplayOutcome::LocallyRefused{..}));
            let wrong_context=FirstPartyCreateContext{observed:"other-context".into()};
            assert!(replay_captured_create_in_transaction(&f.db,&mut tx,&replay_caller,&proposal,&ReplaySavepoint::claim(),&wrong_context).await.is_err());
            let app=owner.clone().with_host_asserted_app(crate::mcp::app_attribution::AppAttribution::new("agent.docs","1","unadmitted-install").unwrap());
            let app_scope=crate::provenance::ProvenanceDispatch::from_caller(&app,"get_record",&json!({"ids":[f.shared]}),None);
            assert!(app_scope.scope(async {FirstPartyCreateContext::observe_current_read(&app)}).await.is_err());
            assert_eq!(proposal.args(),&saved_args);
            assert_eq!(proposal.request_fingerprint(),saved_fp);
            tx.rollback().await.unwrap();f.db.close().await;
        }).await;
    }

    fn null_identity() -> ProposalIdentity {
        ProposalIdentity {
            app: None,
            mint_context: None,
        }
    }

    fn propose(tool: &str, args: Value) -> ReplayProposal {
        propose_as(tool, args, &null_identity())
    }

    fn propose_as(tool: &str, args: Value, identity: &ProposalIdentity) -> ReplayProposal {
        let idempotency_key = args
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::to_owned);
        ReplayProposal::from_original(tool, args, idempotency_key, identity).unwrap()
    }

    async fn replay_one(
        db: &Db,
        actor: &str,
        tx: &mut Transaction<'_, Sqlite>,
        tool: &str,
        args: Value,
    ) -> ReplayOutcome {
        let caller = ReplayCaller {
            actor: actor.to_owned(),
            mint: PendingMintContext,
        };
        let proposal = propose(tool, args);
        let savepoint = ReplaySavepoint::claim();
        replay_write_in_transaction(db, tx, &caller, &proposal, &savepoint)
            .await
            .unwrap()
    }

    fn applied_id(outcome: ReplayOutcome) -> String {
        match outcome {
            ReplayOutcome::Applied {
                touched_record_ids,
                receipt,
            } => {
                assert_eq!(touched_record_ids.len(), 1);
                assert_eq!(touched_record_ids[0], receipt["id"].as_str().unwrap());
                touched_record_ids.into_iter().next().unwrap()
            }
            ReplayOutcome::LocallyRefused { reason } => {
                panic!("expected Applied, locally refused: {reason}")
            }
        }
    }

    /// The allowlisted writes apply through the seam and report the touched
    /// record and the ordinary receipt.
    #[tokio::test]
    async fn replay_applies_allowlisted_writes() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        // Plain note create.
        let create_a = propose(
            "create_record",
            json!({"type":"Document","kind":"note","name":"replayed-a","body":"hello","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-a"}),
        );
        let caller = caller_of(&f);
        let savepoint = ReplaySavepoint::claim();
        let id_a = match replay_write_in_transaction(&f.db, &mut tx, &caller, &create_a, &savepoint)
            .await
            .unwrap()
        {
            ReplayOutcome::Applied {
                touched_record_ids,
                receipt,
            } => {
                assert_eq!(
                    touched_record_ids,
                    vec![receipt["id"].as_str().unwrap().to_owned()]
                );
                assert_eq!(receipt["effect"], "created");
                receipt["id"].as_str().unwrap().to_owned()
            }
            ReplayOutcome::LocallyRefused { reason } => panic!("create refused: {reason}"),
        };
        // Body append on the replayed record.
        let id_a_again = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "update_record",
                json!({"id":id_a,"body_append":" +more","reason":"seam test","idempotency_key":"seam-a-append"}),
            )
            .await,
        );
        assert_eq!(id_a_again, id_a);
        // Second note, then a link add between the two.
        let id_b = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"replayed-b","body":"world","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-b"}),
            )
            .await,
        );
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "manage_links",
            json!({"action":"add","source_id":id_a,"target_id":id_b,"relationship":"mentions","idempotency_key":"seam-link"}),
        )
        .await;
        match outcome {
            ReplayOutcome::Applied {
                touched_record_ids,
                receipt,
            } => {
                assert!(touched_record_ids.contains(&id_a));
                assert!(touched_record_ids.contains(&id_b));
                assert_eq!(receipt["status"], "added");
            }
            ReplayOutcome::LocallyRefused { reason } => panic!("link add refused: {reason}"),
        }
        tx.commit().await.unwrap();
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &id_a)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("hello +more"));
        f.db.close().await;
    }

    /// Eligibility is explicit: tools and shapes outside the allowlist refuse
    /// without running, and proposals that disagree with their arguments are
    /// hard errors.
    #[tokio::test]
    async fn replay_refuses_outside_the_allowlist() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        // Unknown tool.
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "archive_record",
            json!({"id":"does-not-matter","reason":"seam test"}),
        )
        .await;
        assert!(
            matches!(outcome, ReplayOutcome::LocallyRefused { .. }),
            "unexpected: {outcome:?}"
        );
        // manage_links remove is not replayable.
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "manage_links",
            json!({"action":"remove","source_id":"x","target_id":"y","relationship":"mentions"}),
        )
        .await;
        assert!(
            matches!(outcome, ReplayOutcome::LocallyRefused { .. }),
            "unexpected: {outcome:?}"
        );
        // Non-note creates are not replayable.
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "create_record",
            json!({"type":"Collection","kind":"folder","name":"nope","reason":"seam test"}),
        )
        .await;
        assert!(
            matches!(outcome, ReplayOutcome::LocallyRefused { .. }),
            "unexpected: {outcome:?}"
        );
        // Live-body update paths are refused rather than bypassed: a whole
        // body set needs the owned write path.
        let id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"owned","body":"base","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-owned"}),
            )
            .await,
        );
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":id,"body_set":"replaced","reason":"seam test"}),
        )
        .await;
        assert!(
            matches!(outcome, ReplayOutcome::LocallyRefused { .. }),
            "unexpected: {outcome:?}"
        );
        // An internally inconsistent proposal is a hard error, not a refusal.
        let caller = caller_of(&f);
        let bad = propose(
            "create_record",
            json!({"type":"Document","kind":"note","name":"bad","home_id":f.folder.as_str(),"reason":"seam test"}),
        )
        .with_request_fingerprint("deadbeef".into());
        let error =
            replay_write_in_transaction(&f.db, &mut tx, &caller, &bad, &ReplaySavepoint::claim())
                .await
                .unwrap_err();
        assert!(error.to_string().contains("fingerprint"), "{error:?}");
        tx.rollback().await.unwrap();
        f.db.close().await;
    }

    /// Explicit nulls are mutations on the ordinary path, so the allowlist
    /// refuses any non-append key by presence, null or not.
    #[tokio::test]
    async fn replay_refuses_null_mutation_fields() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"null-gate","body":"base","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-null-create"}),
            )
            .await,
        );
        for field in ["maturity", "summary", "lifecycle"] {
            let mut args = serde_json::Map::new();
            args.insert("id".into(), Value::String(id.clone()));
            args.insert("body_append".into(), Value::String(" +x".into()));
            args.insert(field.into(), Value::Null);
            let outcome = replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "update_record",
                Value::Object(args),
            )
            .await;
            match outcome {
                ReplayOutcome::LocallyRefused { reason } => assert!(
                    reason.contains(field),
                    "refusal should name {field}: {reason}"
                ),
                ReplayOutcome::Applied { receipt, .. } => {
                    panic!("null {field} bypassed the allowlist: {receipt}")
                }
            }
        }
        tx.commit().await.unwrap();
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("base"));
        f.db.close().await;
    }

    /// Body append replays only onto visible plain notes: tasks and comments
    /// refuse without running, under either note carrier.
    #[tokio::test]
    async fn replay_body_append_only_applies_to_plain_notes() {
        let f = fixture(false).await;
        // A task created through the ordinary registry path.
        let tools = crate::mcp::kernel_v2::tests::registry();
        let task = tools
            .call_engine(
                crate::mcp::registry::EngineHandle::KernelV2(f.db.clone()),
                caller(&f),
                "create_record",
                json!({"type":"WorkItem","kind":"task","name":"replay-target-task","home_id":f.folder.as_str(),"reason":"seam test"}),
            )
            .await
            .unwrap();
        let task_id = task["id"].as_str().unwrap().to_owned();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        // Task append refused, no mutation.
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":task_id,"body_append":" +task","reason":"seam test"}),
        )
        .await;
        match outcome {
            ReplayOutcome::LocallyRefused { reason } => {
                assert!(reason.contains("non-note"), "unexpected reason: {reason}")
            }
            ReplayOutcome::Applied { receipt, .. } => {
                panic!("task body append bypassed the note gate: {receipt}")
            }
        }
        // Comment append refused: annotations are not plain notes.
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":f.comment,"body_append":" +comment","reason":"seam test"}),
        )
        .await;
        assert!(
            matches!(outcome, ReplayOutcome::LocallyRefused { .. }),
            "unexpected: {outcome:?}"
        );
        // Plain note append applied.
        let note_id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "update_record",
                json!({"id":f.shared,"body_append":" +note","reason":"seam test","idempotency_key":"seam-note-gate"}),
            )
            .await,
        );
        assert_eq!(note_id, f.shared);
        tx.commit().await.unwrap();
        let task = crate::kernel::read_record_as(&f.db, &f.owner_principal, &task_id)
            .await
            .unwrap()
            .unwrap();
        assert!(task.body.is_none(), "refused task append must not mutate");
        let note = crate::kernel::read_record_as(&f.db, &f.owner_principal, &f.shared)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(note.body.as_deref(), Some("shared before +note"));
        f.db.close().await;
    }

    /// Visibility comes before the live-room check: a hidden target with an
    /// open room reports exactly what a missing target reports, and neither
    /// mutates anything.
    #[tokio::test]
    async fn replay_hidden_target_matches_missing_target() {
        let f = fixture(false).await;
        // Open a live room on the owner-only record: a leaked oracle would
        // finger it, but the member must see the uniform refusal instead.
        let owner_caller = caller(&f);
        let (_peer, _opened) = kernel_writes::open_for_test(
            &f.db,
            &owner_caller,
            OpenRequest {
                record_id: f.private.clone(),
                mode: PeerKind::Edit,
                resume_peer: None,
            },
        )
        .await
        .unwrap();
        let member = ReplayCaller {
            actor: f.member_principal.clone(),
            mint: PendingMintContext,
        };
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let hidden = replay_write_in_transaction(
            &f.db,
            &mut tx,
            &member,
            &propose(
                "update_record",
                json!({"id":f.private,"body_append":" sneak","reason":"seam test"}),
            ),
            &ReplaySavepoint::claim(),
        )
        .await
        .unwrap();
        let missing = replay_write_in_transaction(
            &f.db,
            &mut tx,
            &member,
            &propose(
                "update_record",
                json!({"id":"00000000-0000-0000-0000-000000000000","body_append":" sneak","reason":"seam test"}),
            ),
            &ReplaySavepoint::claim(),
        )
        .await
        .unwrap();
        match (hidden, missing) {
            (
                ReplayOutcome::LocallyRefused { reason: hidden },
                ReplayOutcome::LocallyRefused { reason: missing },
            ) => assert_eq!(
                hidden, missing,
                "hidden and missing targets must refuse identically"
            ),
            (hidden, missing) => panic!("unexpected outcomes: {hidden:?} vs {missing:?}"),
        }
        tx.rollback().await.unwrap();
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &f.private)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("private before"));
        f.db.close().await;
    }

    /// Install an actual ambient app dispatch identity, then replay a
    /// null-identity proposal: it fails closed with no mutation and no
    /// receipt, because the caller's supported boundary is no ambient
    /// app/dispatch identity scope.
    #[tokio::test]
    async fn replay_under_app_scope_fails_closed_with_no_mutation() {
        let f = fixture(false).await;
        let claim = crate::mcp::app_attribution::AppAttribution::new(
            "example.replay-scope",
            "1.0.0",
            "install-scope",
        )
        .unwrap();
        let scoped = caller(&f).with_host_asserted_app(claim);
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &scoped,
            "update_record",
            &json!({"id": f.shared}),
            None,
        );
        let proposal = propose(
            "update_record",
            json!({"id":f.shared,"body_append":" +scoped","reason":"seam test","idempotency_key":"seam-app-scope-refusal"}),
        );
        let outcome = dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                let outcome = replay_write_in_transaction(
                    &f.db,
                    &mut tx,
                    &caller_of(&f),
                    &proposal,
                    &ReplaySavepoint::claim(),
                )
                .await
                .unwrap();
                tx.rollback().await.unwrap();
                outcome
            })
            .await;
        match outcome {
            ReplayOutcome::LocallyRefused { reason } => assert!(
                reason.contains(crate::mcp::kernel_v2::writes::replay::AMBIENT_IDENTITY_MISMATCH),
                "unexpected reason: {reason}"
            ),
            ReplayOutcome::Applied { receipt, .. } => {
                panic!("app-scoped replay must fail closed: {receipt}")
            }
        }
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &f.shared)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("shared before"));
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='update_record' AND operation_key='seam-app-scope-refusal'",
        )
        .bind(&f.owner_principal)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        assert_eq!(receipts, 0, "refused replay must not touch the ledger");
        f.db.close().await;
    }

    /// With no ambient scope, replay succeeds and the stored ledger
    /// fingerprint is byte-equal to the proposal's request fingerprint.
    #[tokio::test]
    async fn replay_scopeless_stores_proposal_fingerprint_bytes() {
        let f = fixture(false).await;
        let proposal = propose(
            "create_record",
            json!({"type":"Document","kind":"note","name":"ledger-bytes","body":"kept","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-ledger-bytes"}),
        );
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let outcome = replay_write_in_transaction(
            &f.db,
            &mut tx,
            &caller_of(&f),
            &proposal,
            &ReplaySavepoint::claim(),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, ReplayOutcome::Applied { .. }),
            "unexpected: {outcome:?}"
        );
        tx.commit().await.unwrap();
        let stored: String = sqlx::query_scalar(
            "SELECT request_json FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='create_record' AND operation_key='seam-ledger-bytes'",
        )
        .bind(&f.owner_principal)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        assert_eq!(
            stored,
            proposal.request_fingerprint().to_owned(),
            "the ledger must store the proposal's fingerprint bytes"
        );
        f.db.close().await;
    }

    /// A stored-receipt retry under no ambient scope returns the original
    /// receipt; the same retry under an app scope refuses instead.
    #[tokio::test]
    async fn replay_stored_retry_needs_matching_scope() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let first = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":f.shared,"body_append":" +scoped-retry","reason":"seam test","idempotency_key":"seam-scope-retry"}),
        )
        .await;
        let first_receipt = match first {
            ReplayOutcome::Applied { receipt, .. } => receipt,
            ReplayOutcome::LocallyRefused { reason } => {
                panic!("setup replay refused: {reason}")
            }
        };
        tx.commit().await.unwrap();
        // Scopeless retry: the stored receipt, no second mutation.
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let retry = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":f.shared,"body_append":" +scoped-retry","reason":"seam test","idempotency_key":"seam-scope-retry"}),
        )
        .await;
        match retry {
            ReplayOutcome::Applied { receipt, .. } => assert_eq!(receipt, first_receipt),
            ReplayOutcome::LocallyRefused { reason } => {
                panic!("scopeless retry must return the stored receipt: {reason}")
            }
        }
        tx.commit().await.unwrap();
        // Same retry under an app scope: fail closed, no mutation.
        let claim = crate::mcp::app_attribution::AppAttribution::new(
            "example.replay-scope",
            "1.0.0",
            "install-scope",
        )
        .unwrap();
        let scoped = caller(&f).with_host_asserted_app(claim);
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &scoped,
            "update_record",
            &json!({"id": f.shared}),
            None,
        );
        let outcome = dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                let outcome = replay_one(
                    &f.db,
                    &f.owner_principal,
                    &mut tx,
                    "update_record",
                    json!({"id":f.shared,"body_append":" +scoped-retry","reason":"seam test","idempotency_key":"seam-scope-retry"}),
                )
                .await;
                tx.rollback().await.unwrap();
                outcome
            })
            .await;
        match outcome {
            ReplayOutcome::LocallyRefused { reason } => assert!(
                reason.contains(crate::mcp::kernel_v2::writes::replay::AMBIENT_IDENTITY_MISMATCH),
                "unexpected reason: {reason}"
            ),
            ReplayOutcome::Applied { receipt, .. } => {
                panic!("app-scoped retry must fail closed: {receipt}")
            }
        }
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &f.shared)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("shared before +scoped-retry"));
        f.db.close().await;
    }

    /// A body append on a record with an open live body session refuses: the
    /// live room owns that write path.
    #[tokio::test]
    async fn replay_refuses_body_append_with_an_open_live_room() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"live","body":"base","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-live"}),
            )
            .await,
        );
        tx.commit().await.unwrap();
        // Open a live editing session on the record and keep it alive.
        let live_caller = caller(&f);
        let (_peer, _opened) = kernel_writes::open_for_test(
            &f.db,
            &live_caller,
            OpenRequest {
                record_id: id.clone(),
                mode: PeerKind::Edit,
                resume_peer: None,
            },
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":id,"body_append":" bypass","reason":"seam test"}),
        )
        .await;
        match outcome {
            ReplayOutcome::LocallyRefused { reason } => assert!(
                reason.contains("live body session"),
                "unexpected reason: {reason}"
            ),
            ReplayOutcome::Applied { receipt, .. } => {
                panic!("replay bypassed live-body ownership: {receipt}")
            }
        }
        tx.rollback().await.unwrap();
        f.db.close().await;
    }

    /// An exact keyed retry returns the stored receipt without another body
    /// mutation even while a live room is open — the receipt lookup runs
    /// before the live-room refusal, as on the ordinary path.
    #[tokio::test]
    async fn replay_keyed_retry_with_open_live_room_returns_stored_receipt() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "update_record",
                json!({"id":f.shared,"body_append":" +once","reason":"seam test","idempotency_key":"seam-live-retry"}),
            )
            .await,
        );
        assert_eq!(id, f.shared);
        tx.commit().await.unwrap();
        let head_before: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        // Open a live editing session on the note and keep it alive.
        let live_caller = caller(&f);
        let (_peer, _opened) = kernel_writes::open_for_test(
            &f.db,
            &live_caller,
            OpenRequest {
                record_id: id.clone(),
                mode: PeerKind::Edit,
                resume_peer: None,
            },
        )
        .await
        .unwrap();
        // The identical proposal replays the stored receipt: no live-room
        // refusal, no second body mutation, no new act.
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":f.shared,"body_append":" +once","reason":"seam test","idempotency_key":"seam-live-retry"}),
        )
        .await;
        let receipt = match outcome {
            ReplayOutcome::Applied { receipt, .. } => receipt,
            ReplayOutcome::LocallyRefused { reason } => {
                panic!("exact retry must return the stored receipt: {reason}")
            }
        };
        assert_eq!(receipt["id"].as_str(), Some(id.as_str()));
        tx.commit().await.unwrap();
        let head_after: i64 =
            sqlx::query_scalar("SELECT next_act FROM act_state WHERE singleton=1")
                .fetch_one(f.db.pool())
                .await
                .unwrap();
        assert_eq!(
            head_before, head_after,
            "a stored-receipt retry advances no act"
        );
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            record.body.as_deref(),
            Some("shared before +once"),
            "a stored-receipt retry appends nothing"
        );
        f.db.close().await;
    }

    /// A new keyed append with an open room still refuses: only exact retries
    /// bypass the live-room fence.
    #[tokio::test]
    async fn replay_new_key_with_open_live_room_refuses() {
        let f = fixture(false).await;
        let live_caller = caller(&f);
        let (_peer, _opened) = kernel_writes::open_for_test(
            &f.db,
            &live_caller,
            OpenRequest {
                record_id: f.shared.clone(),
                mode: PeerKind::Edit,
                resume_peer: None,
            },
        )
        .await
        .unwrap();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let outcome = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "update_record",
            json!({"id":f.shared,"body_append":" +new-key","reason":"seam test","idempotency_key":"seam-live-new-key"}),
        )
        .await;
        match outcome {
            ReplayOutcome::LocallyRefused { reason } => assert!(
                reason.contains("live body session"),
                "unexpected reason: {reason}"
            ),
            ReplayOutcome::Applied { receipt, .. } => {
                panic!("new keyed append bypassed live-body ownership: {receipt}")
            }
        }
        tx.rollback().await.unwrap();
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &f.shared)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("shared before"));
        f.db.close().await;
    }

    /// Replaying the same keyed proposal twice returns the stored receipt with
    /// no duplicate effect.
    #[tokio::test]
    async fn replay_same_key_returns_stored_receipt_once() {
        let f = fixture(false).await;
        let records_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let args = json!({"type":"Document","kind":"note","name":"keyed","body":"once","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-idem-once"});
        let first = replay_one(
            &f.db,
            &f.owner_principal,
            &mut tx,
            "create_record",
            args.clone(),
        )
        .await;
        let second = replay_one(&f.db, &f.owner_principal, &mut tx, "create_record", args).await;
        match (first, second) {
            (
                ReplayOutcome::Applied {
                    touched_record_ids: first_ids,
                    receipt: first_receipt,
                },
                ReplayOutcome::Applied {
                    touched_record_ids: second_ids,
                    receipt: second_receipt,
                },
            ) => {
                assert_eq!(first_ids, second_ids);
                assert_eq!(
                    first_receipt, second_receipt,
                    "the retry must return the stored receipt bytes"
                );
            }
            (first, second) => panic!("unexpected outcomes: {first:?} vs {second:?}"),
        }
        tx.commit().await.unwrap();
        let records_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        assert_eq!(records_after, records_before + 1, "no duplicate record");
        f.db.close().await;
    }

    /// Reusing an idempotency key for a different request refuses locally: the
    /// keyed retry path replays the stored outcome only for the identical
    /// request.
    #[tokio::test]
    async fn replay_key_reused_for_different_request_refuses() {
        let f = fixture(false).await;
        let records_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"first-writer","body":"one","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-idem-conflict"}),
            )
            .await,
        );
        // Same key, different request body: the fingerprint matches the new
        // arguments, but the key is already bound to the first request.
        let caller = caller_of(&f);
        let conflicting = propose(
            "create_record",
            json!({"type":"Document","kind":"note","name":"second-writer","body":"two","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-idem-conflict"}),
        );
        let outcome = replay_write_in_transaction(
            &f.db,
            &mut tx,
            &caller,
            &conflicting,
            &ReplaySavepoint::claim(),
        )
        .await
        .unwrap();
        match outcome {
            ReplayOutcome::LocallyRefused { reason } => assert!(
                reason.contains("idempotency_key"),
                "unexpected reason: {reason}"
            ),
            ReplayOutcome::Applied { receipt, .. } => {
                panic!("conflicting key reuse applied: {receipt}")
            }
        }
        tx.commit().await.unwrap();
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("one"));
        let records_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        assert_eq!(
            records_after,
            records_before + 1,
            "conflicting retry must not create a record"
        );
        f.db.close().await;
    }

    /// Dropping a replay future before its first poll opens nothing: the
    /// documented cleanup reports "no such savepoint", and the caller rolls
    /// back the untouched outer transaction.
    #[tokio::test]
    async fn replay_drop_before_first_poll_rolls_back_untouched() {
        let f = fixture(false).await;
        let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let savepoint = ReplaySavepoint::claim();
        let caller = caller_of(&f);
        let proposal = propose(
            "create_record",
            json!({"type":"Document","kind":"note","name":"never-ran","body":"never","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-drop"}),
        );
        {
            let future =
                replay_write_in_transaction(&f.db, &mut tx, &caller, &proposal, &savepoint);
            drop(future);
        }
        let error = savepoint.rollback_abandoned(&mut tx).await.unwrap_err();
        assert!(
            error.to_string().contains("no such savepoint"),
            "unexpected error: {error:?}"
        );
        tx.rollback().await.unwrap();
        let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
            .fetch_one(f.db.pool())
            .await
            .unwrap();
        assert_eq!(before, after, "nothing ran, nothing changed");
        f.db.close().await;
    }

    /// Cancelling after the mutation but before the release rolls the partial
    /// work back with the savepoint: the body keeps its original text, no
    /// receipt row survives, and the outer transaction stays usable.
    #[tokio::test]
    async fn replay_cancel_after_mutation_before_release_leaves_no_trace() {
        use super::cancellation_probe;
        use std::future::Future;

        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let savepoint = ReplaySavepoint::claim();
        let caller = caller_of(&f);
        let proposal = propose(
            "update_record",
            json!({"id":f.shared,"body_append":" +aborted?","reason":"seam test","idempotency_key":"seam-abort-key"}),
        );
        cancellation_probe::arm_before_release();
        {
            let mut future = Box::pin(replay_write_in_transaction(
                &f.db, &mut tx, &caller, &proposal, &savepoint,
            ));
            // Drive until the hook pauses the replay after its mutation.
            let waker = futures::task::noop_waker();
            let mut context = std::task::Context::from_waker(&waker);
            while !cancellation_probe::reached_before_release() {
                assert!(
                    future.as_mut().poll(&mut context).is_pending(),
                    "the replay must pause at the hook, not finish"
                );
            }
            // Drop mid-savepoint, as a cancelled task would.
            drop(future);
        }
        savepoint.rollback_abandoned(&mut tx).await.unwrap();
        // The aborted append is gone from the body and the receipt ledger,
        // read on the same still-usable transaction.
        let view = super::super::view(&mut tx, &f.owner_principal, &f.shared)
            .await
            .unwrap();
        assert_eq!(view.body.as_deref(), Some("shared before"));
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='update_record' AND operation_key='seam-abort-key'",
        )
        .bind(&f.owner_principal)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(receipts, 0, "no receipt survives the aborted append");
        tx.commit().await.unwrap();
        let view = super::super::view(
            &mut f.db.pool().acquire().await.unwrap(),
            &f.owner_principal,
            &f.shared,
        )
        .await
        .unwrap();
        assert_eq!(view.body.as_deref(), Some("shared before"));
        f.db.close().await;
    }

    /// Cancelling after the release can no longer unwind the savepoint: the
    /// documented cleanup reports "no such savepoint", so the caller rolls
    /// back the outer transaction, and the mutation vanishes with it.
    #[tokio::test]
    async fn replay_cancel_after_release_rolls_back_the_outer_transaction() {
        use super::cancellation_probe;
        use std::future::Future;

        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let savepoint = ReplaySavepoint::claim();
        let caller = caller_of(&f);
        let proposal = propose(
            "update_record",
            json!({"id":f.shared,"body_append":" +aborted-after-release?","reason":"seam test","idempotency_key":"seam-abort-release-key"}),
        );
        cancellation_probe::arm_after_release();
        {
            let mut future = Box::pin(replay_write_in_transaction(
                &f.db, &mut tx, &caller, &proposal, &savepoint,
            ));
            // Drive until the hook pauses the replay after its release.
            let waker = futures::task::noop_waker();
            let mut context = std::task::Context::from_waker(&waker);
            while !cancellation_probe::reached_after_release() {
                assert!(
                    future.as_mut().poll(&mut context).is_pending(),
                    "the replay must pause at the hook, not finish"
                );
            }
            drop(future);
        }
        // The savepoint is already released: cleanup cannot establish the
        // rollback, so per the docs the outer transaction rolls back.
        let error = savepoint.rollback_abandoned(&mut tx).await.unwrap_err();
        assert!(
            error.to_string().contains("no such savepoint"),
            "unexpected error: {error:?}"
        );
        tx.rollback().await.unwrap();
        let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &f.shared)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("shared before"));
        let receipts: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM kernel_mcp_write_receipts WHERE principal_id=? AND operation='update_record' AND operation_key='seam-abort-release-key'",
        )
        .bind(&f.owner_principal)
        .fetch_one(f.db.pool())
        .await
        .unwrap();
        assert_eq!(receipts, 0, "no receipt survives the rolled-back append");
        f.db.close().await;
    }

    /// Two replayed writes plus a fold commit together in one outer
    /// transaction; rolled back, the database is exactly as before. The fold
    /// runs first (the accepted delta starts at the outer head), then the
    /// pending writes replay on top — the future working-copy rebase shape.
    #[tokio::test]
    async fn replay_and_fold_commit_and_roll_back_atomically() {
        use crate::standby::delta_transport::AuthorityActTransport;
        use crate::standby::kernel_v2_delta::{
            certify_fold_in_transaction, fold_in_transaction, ApplyMode,
        };
        use crate::standby::phase_timings::PhaseTimings;

        async fn coordinates_of(db: &Db) -> crate::standby::kernel_v2::KernelGeneration {
            let mut conn = db.pool().acquire().await.unwrap();
            crate::standby::kernel_v2::coordinates(&mut conn)
                .await
                .unwrap()
        }

        for commit in [true, false] {
            let f = fixture(false).await;
            let dir = tempfile::tempdir().unwrap();
            // One setup write so the head is past genesis, then fork the file.
            let mut setup_tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let setup_id = applied_id(
                replay_one(
                    &f.db,
                    &f.owner_principal,
                    &mut setup_tx,
                    "create_record",
                    json!({"type":"Document","kind":"note","name":"setup","body":"setup","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"atomic-setup"}),
                )
                .await,
            );
            setup_tx.commit().await.unwrap();
            assert!(
                crate::kernel::read_record_as(&f.db, &f.owner_principal, &setup_id)
                    .await
                    .unwrap()
                    .is_some()
            );
            let base = coordinates_of(&f.db).await;
            let fork_path = dir.path().join("fork.db");
            let escaped = fork_path.display().to_string().replace('\'', "''");
            sqlx::query(&format!("VACUUM INTO '{escaped}'"))
                .execute(f.db.write_pool())
                .await
                .unwrap();
            let fork_db = crate::kernel::open_v2_database(fork_path.to_str().unwrap())
                .await
                .unwrap();
            let fork_actor = f.owner_principal.clone();
            // Two ordinary writes on the fork; the delta covers exactly them.
            for (key, name) in [("fork-1", "fork-a"), ("fork-2", "fork-b")] {
                let mut tx = crate::db::begin_write(fork_db.write_pool()).await.unwrap();
                applied_id(
                    replay_one(
                        &fork_db,
                        &fork_actor,
                        &mut tx,
                        "create_record",
                        json!({"type":"Document","kind":"note","name":name,"body":"forked","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":key}),
                    )
                    .await,
                );
                tx.commit().await.unwrap();
            }
            let head =
                crate::standby::delta_transport::observe_authority_act_head(&fork_db, "route-1")
                    .await
                    .unwrap();
            let origin = head.head().origin_database_id().to_owned();
            let transport = AuthorityActTransport::with_client(
                "https://fixture.example",
                "route-1",
                &origin,
                "test-token",
                Arc::new(Hosted(fork_db.clone())),
            )
            .unwrap();
            transport.head().await.unwrap();
            let delta = transport.kernel_delta(base.head_act, &[]).await.unwrap();
            assert!(delta.delta().head.head_act > base.head_act);
            let before_dump = crate::kernel::dump_all_kernel_tables(&f.db).await.unwrap();
            let records_before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
                .fetch_one(f.db.pool())
                .await
                .unwrap();
            // One outer transaction: fold the accepted delta, replay two
            // pending writes on top.
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let timings = PhaseTimings::default();
            let folded = fold_in_transaction(&mut tx, &delta, &timings, ApplyMode::Staged)
                .await
                .unwrap();
            assert_eq!(folded.before().head_act, base.head_act);
            let certified = certify_fold_in_transaction(&mut tx, &delta, folded, &timings)
                .await
                .unwrap();
            assert!(certified.receipt.is_none());
            let id_a = applied_id(
                replay_one(
                    &f.db,
                    &f.owner_principal,
                    &mut tx,
                    "create_record",
                    json!({"type":"Document","kind":"note","name":"pending-a","body":"pending","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"atomic-a"}),
                )
                .await,
            );
            let id_b = applied_id(
                replay_one(
                    &f.db,
                    &f.owner_principal,
                    &mut tx,
                    "update_record",
                    json!({"id":id_a,"body_append":" +appended","reason":"seam test","idempotency_key":"atomic-b"}),
                )
                .await,
            );
            assert_eq!(id_a, id_b);
            if commit {
                tx.commit().await.unwrap();
                let after = coordinates_of(&f.db).await;
                assert_eq!(after.head_act, certified.facts.to_act + 2);
                let record = crate::kernel::read_record_as(&f.db, &f.owner_principal, &id_a)
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(record.body.as_deref(), Some("pending +appended"));
                let records_after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records")
                    .fetch_one(f.db.pool())
                    .await
                    .unwrap();
                assert_eq!(
                    records_after,
                    records_before + 3,
                    "the two folded fork records plus the replayed pending note"
                );
            } else {
                tx.rollback().await.unwrap();
                assert_eq!(coordinates_of(&f.db).await, base);
                assert_eq!(
                    crate::kernel::dump_all_kernel_tables(&f.db).await.unwrap(),
                    before_dump,
                    "rollback leaves the database exactly as before"
                );
                let pending: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM kernel_records WHERE id=?")
                        .bind(&id_a)
                        .fetch_one(f.db.pool())
                        .await
                        .unwrap();
                assert_eq!(pending, 0);
            }
            fork_db.close().await;
            f.db.close().await;
        }
    }

    /// The helper and ordinary dispatch agree under the same scope, setting on
    /// and off, and the historical envelopes hash exactly as before.
    #[tokio::test]
    async fn proposal_fingerprint_matches_dispatch_and_pins_history() {
        use super::super::MINTED_IDS_TEST;
        use crate::kernel::mcp_write_receipts::intent_fingerprint;

        let plain = json!({"type":"Document","kind":"note","name":"pinned","home_id":"native:root","reason":"pin"});
        let nonce = json!({"type":"Document","kind":"note","name":"pinned","home_id":"native:root","reason":"pin","id_nonce":"nonce-pin","id":"00000000-0000-0000-0000-000000000001"});
        let app = json!({"account":"acct:pin","package":"document","version":4,"install_event_id":"evt-pin"});
        let null = ProposalIdentity {
            app: None,
            mint_context: None,
        };
        // App-null: no identity anywhere.
        assert_eq!(
            proposal_fingerprint("create_record", &plain, &null).unwrap(),
            intent_fingerprint("create_record", plain.clone(), Value::Null).unwrap(),
        );
        // Helper and dispatch agree under the same (empty) ambient scope,
        // with the mint setting on and off: no nonce, so app-only either way.
        for enabled in [false, true] {
            MINTED_IDS_TEST
                .scope(enabled, async {
                    assert_eq!(
                        proposal_fingerprint("create_record", &plain, &null).unwrap(),
                        super::super::dispatched_fingerprint("create_record", plain.clone())
                            .unwrap(),
                    );
                })
                .await;
        }
        // App-only envelope with an explicit claim.
        let app_only = ProposalIdentity {
            app: Some(app.clone()),
            mint_context: None,
        };
        assert_eq!(
            proposal_fingerprint("create_record", &nonce, &app_only).unwrap(),
            intent_fingerprint("create_record", nonce.clone(), app.clone()).unwrap(),
        );
        // Compound envelope: the exact historical shape.
        let compound = ProposalIdentity {
            app: Some(app.clone()),
            mint_context: Some("ctx-pin".into()),
        };
        assert_eq!(
            proposal_fingerprint("create_record", &nonce, &compound).unwrap(),
            intent_fingerprint(
                "create_record",
                nonce.clone(),
                json!({"app": app, "mint_context": "ctx-pin"}),
            )
            .unwrap(),
        );
        // The compound bytes differ from the app-only bytes for the same
        // arguments, and the mint context is inert without an id_nonce.
        assert_ne!(
            proposal_fingerprint("create_record", &nonce, &compound).unwrap(),
            proposal_fingerprint("create_record", &nonce, &app_only).unwrap(),
        );
        assert_eq!(
            proposal_fingerprint("create_record", &plain, &compound).unwrap(),
            proposal_fingerprint("create_record", &plain, &app_only).unwrap(),
        );
    }

    /// An explicit JSON null app normalizes to the unset identity: same
    /// stored bytes, and the proposal replays successfully with no ambient
    /// scope instead of tripping the ambient mismatch.
    #[tokio::test]
    async fn replay_explicit_null_identity_matches_scopeless_ambient() {
        let null = null_identity();
        let f = fixture(false).await;
        let args = json!({"type":"Document","kind":"note","name":"null-app","body":"kept","home_id":f.folder.as_str(),"reason":"pin","idempotency_key":"seam-explicit-null"});
        let explicit = ProposalIdentity {
            app: Some(Value::Null),
            mint_context: None,
        };
        let proposal = ReplayProposal::from_original(
            "create_record",
            args.clone(),
            Some("seam-explicit-null".into()),
            &explicit,
        )
        .unwrap();
        assert_eq!(proposal.identity(), &null);
        assert_eq!(
            proposal.request_fingerprint(),
            proposal_fingerprint("create_record", &args, &null)
                .unwrap()
                .as_str()
        );
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let outcome = replay_write_in_transaction(
            &f.db,
            &mut tx,
            &caller_of(&f),
            &proposal,
            &ReplaySavepoint::claim(),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, ReplayOutcome::Applied { .. }),
            "unexpected: {outcome:?}"
        );
        tx.rollback().await.unwrap();
        f.db.close().await;
    }

    /// `from_original` rejects key disagreement and stores the identity and
    /// fingerprint immutably.
    #[test]
    fn from_original_rejects_key_disagreement() {
        let null = ProposalIdentity {
            app: None,
            mint_context: None,
        };
        let args = json!({"type":"Document","kind":"note","name":"keyed","home_id":"native:root","reason":"pin","idempotency_key":"args-key"});
        let error = ReplayProposal::from_original(
            "create_record",
            args.clone(),
            Some("other-key".into()),
            &null,
        )
        .unwrap_err();
        assert!(error.to_string().contains("disagrees"), "{error:?}");
        let mut keyless = args.clone();
        keyless.as_object_mut().unwrap().remove("idempotency_key");
        let error = ReplayProposal::from_original(
            "create_record",
            keyless,
            Some("param-key".into()),
            &null,
        )
        .unwrap_err();
        assert!(error.to_string().contains("disagrees"), "{error:?}");
        let error =
            ReplayProposal::from_original("create_record", args.clone(), None, &null).unwrap_err();
        assert!(error.to_string().contains("disagrees"), "{error:?}");
        let proposal = ReplayProposal::from_original(
            "create_record",
            args.clone(),
            Some("args-key".into()),
            &null,
        )
        .unwrap();
        assert_eq!(proposal.idempotency_key.as_deref(), Some("args-key"));
        assert_eq!(proposal.identity(), &null);
        assert_eq!(
            proposal.request_fingerprint(),
            proposal_fingerprint("create_record", &args, &null).unwrap()
        );
    }

    /// With no ambient scope, the ingress constructor succeeds and its request
    /// fingerprint is byte-equal to `dispatched_fingerprint` under the same
    /// scope: both select identity through `ambient_proposal_identity`.
    #[test]
    fn from_current_first_party_matches_dispatched_fingerprint_scopeless() {
        let args = json!({"type":"Document","kind":"note","name":"ingress","body":"kept","home_id":"native:root","reason":"ingress test","idempotency_key":"seam-ingress-fp"});
        let proposal = ReplayProposal::from_current_first_party(
            "create_record",
            args.clone(),
            Some("seam-ingress-fp".into()),
        )
        .unwrap();
        assert_eq!(
            proposal.request_fingerprint(),
            super::super::dispatched_fingerprint("create_record", args)
                .unwrap()
                .as_str(),
            "ingress and dispatch must fingerprint the same bytes under the same scope"
        );
    }

    /// With a real ambient app dispatch scope installed (as the existing
    /// app-scope replay tests install it), the ingress constructor refuses
    /// with `NonFirstPartyIdentity` instead of journaling under that scope.
    #[tokio::test]
    async fn from_current_first_party_refuses_under_app_scope() {
        let f = fixture(false).await;
        let claim = crate::mcp::app_attribution::AppAttribution::new(
            "example.replay-scope",
            "1.0.0",
            "install-scope",
        )
        .unwrap();
        let scoped = caller(&f).with_host_asserted_app(claim);
        let args = json!({"type":"Document","kind":"note","name":"ingress-scoped","body":"kept","home_id":f.folder.as_str(),"reason":"ingress test"});
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &scoped,
            "create_record",
            &args,
            None,
        );
        let error = dispatch
            .scope(async {
                ReplayProposal::from_current_first_party("create_record", args.clone(), None)
                    .unwrap_err()
            })
            .await;
        assert!(
            matches!(error, crate::Error::Engine(_)),
            "ingress refusal stays a hard engine error: {error:?}"
        );
        assert!(
            error.to_string().contains(super::NON_FIRST_PARTY_IDENTITY),
            "unexpected error: {error:?}"
        );
        f.db.close().await;
    }

    /// With minted IDs enabled and an `id_nonce` present, the ambient selector
    /// picks a mint context (no app claim anywhere); the ingress constructor
    /// refuses with `NonFirstPartyIdentity`.
    #[tokio::test]
    async fn from_current_first_party_refuses_mint_context() {
        use super::super::MINTED_IDS_TEST;
        let f = fixture(false).await;
        let args = json!({"type":"Document","kind":"note","name":"ingress-minted","home_id":f.folder.as_str(),"reason":"ingress test","id_nonce":"nonce-ingress"});
        let plain = caller(&f);
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &plain,
            "create_record",
            &args,
            None,
        );
        MINTED_IDS_TEST
            .scope(
                true,
                dispatch.scope(async {
                    // Prove the mint half is what fires: no app claim, but a mint
                    // context is selected.
                    let ambient =
                        super::super::ambient_proposal_identity("create_record", &args).unwrap();
                    assert!(ambient.app.is_none(), "unexpected app claim: {ambient:?}");
                    assert!(
                        ambient.mint_context.is_some(),
                        "expected a mint context: {ambient:?}"
                    );
                    let error = ReplayProposal::from_current_first_party(
                        "create_record",
                        args.clone(),
                        None,
                    )
                    .unwrap_err();
                    assert!(
                        error.to_string().contains(super::NON_FIRST_PARTY_IDENTITY),
                        "unexpected error: {error:?}"
                    );
                }),
            )
            .await;
        f.db.close().await;
    }

    /// A proposal captured at ingress replays successfully through the
    /// ordinary seam with no ambient scope.
    #[tokio::test]
    async fn from_current_first_party_proposal_replays_scopeless() {
        let f = fixture(false).await;
        let proposal = ReplayProposal::from_current_first_party(
            "create_record",
            json!({"type":"Document","kind":"note","name":"ingress-replay","body":"kept","home_id":f.folder.as_str(),"reason":"ingress test","idempotency_key":"seam-ingress-replay"}),
            Some("seam-ingress-replay".into()),
        )
        .unwrap();
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let outcome = replay_write_in_transaction(
            &f.db,
            &mut tx,
            &caller_of(&f),
            &proposal,
            &ReplaySavepoint::claim(),
        )
        .await
        .unwrap();
        assert!(
            matches!(outcome, ReplayOutcome::Applied { .. }),
            "unexpected: {outcome:?}"
        );
        tx.commit().await.unwrap();
        f.db.close().await;
    }

    /// A key/args disagreement is still a hard error through the ingress
    /// constructor, via `from_original`.
    #[test]
    fn from_current_first_party_rejects_key_disagreement() {
        let args = json!({"type":"Document","kind":"note","name":"keyed","home_id":"native:root","reason":"ingress test","idempotency_key":"args-key"});
        let error = ReplayProposal::from_current_first_party(
            "create_record",
            args,
            Some("other-key".into()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("disagrees"), "{error:?}");
    }

    /// After constructing an original proposal, a changed mint setting — or
    /// no ambient scope at all — alters neither the stored fingerprint nor
    /// the replay outcome.
    #[tokio::test]
    async fn replay_outcome_survives_scope_changes() {
        use super::super::MINTED_IDS_TEST;

        let f = fixture(false).await;
        let args = json!({"type":"Document","kind":"note","name":"scope-proof","body":"kept","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-scope"});
        let proposal = ReplayProposal::from_original(
            "create_record",
            args,
            Some("seam-scope".into()),
            &null_identity(),
        )
        .unwrap();
        let fingerprint = proposal.request_fingerprint.clone();
        for enabled in [false, true] {
            MINTED_IDS_TEST
                .scope(enabled, async {
                    // The stored bytes never move with ambient scope.
                    assert_eq!(
                        proposal_fingerprint(proposal.tool(), proposal.args(), &null_identity())
                            .unwrap(),
                        fingerprint
                    );
                    assert_eq!(proposal.request_fingerprint(), fingerprint.as_str());
                    // ...and the replay outcome is identical.
                    let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
                    let caller = caller_of(&f);
                    let outcome = replay_write_in_transaction(
                        &f.db,
                        &mut tx,
                        &caller,
                        &proposal,
                        &ReplaySavepoint::claim(),
                    )
                    .await
                    .unwrap();
                    assert!(
                        matches!(outcome, ReplayOutcome::Applied { .. }),
                        "unexpected: {outcome:?}"
                    );
                    tx.rollback().await.unwrap();
                })
                .await;
        }
        f.db.close().await;
    }

    /// A non-null original identity fails closed with a local refusal until
    /// the admission wiring lands — for an app claim and for a mint context
    /// alike — without running the write.
    #[tokio::test]
    async fn replay_non_null_identity_fails_closed() {
        let f = fixture(false).await;
        for identity in [
            ProposalIdentity {
                app: Some(json!({"account":"acct:foreign"})),
                mint_context: None,
            },
            ProposalIdentity {
                app: None,
                mint_context: Some("foreign-context".into()),
            },
        ] {
            let proposal = ReplayProposal::from_original(
                "create_record",
                json!({"type":"Document","kind":"note","name":"foreign","body":"never","home_id":f.folder.as_str(),"reason":"seam test"}),
                None,
                &identity,
            )
            .unwrap();
            let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
            let outcome = replay_write_in_transaction(
                &f.db,
                &mut tx,
                &caller_of(&f),
                &proposal,
                &ReplaySavepoint::claim(),
            )
            .await
            .unwrap();
            match outcome {
                ReplayOutcome::LocallyRefused { reason } => assert!(
                    reason.contains("admission wiring"),
                    "unexpected reason: {reason}"
                ),
                ReplayOutcome::Applied { receipt, .. } => {
                    panic!("non-null identity must fail closed: {receipt}")
                }
            }
            tx.rollback().await.unwrap();
        }
        f.db.close().await;
    }

    /// A dropped (cancelled) replay leaves its savepoint open, which its
    /// caller cleans up with [`ReplaySavepoint::rollback_abandoned`]: the
    /// partial work vanishes and the outer transaction stays usable.
    #[tokio::test]
    async fn replay_savepoint_can_be_rolled_back_after_abandon() {
        let f = fixture(false).await;
        let mut tx = crate::db::begin_write(f.db.write_pool()).await.unwrap();
        let savepoint = ReplaySavepoint::claim();
        // Simulate a replay future dropped after opening its savepoint: some
        // partial work sits inside it.
        sqlx::query(&format!("SAVEPOINT {}", savepoint.name()))
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE seam_probe(x TEXT)")
            .execute(&mut *tx)
            .await
            .unwrap();
        savepoint.rollback_abandoned(&mut tx).await.unwrap();
        // Read through the same transaction: the abandoned table is gone.
        let probes: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name='seam_probe'",
        )
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert_eq!(probes, 0);
        // The outer transaction is still usable afterwards.
        let id = applied_id(
            replay_one(
                &f.db,
                &f.owner_principal,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"after-abandon","body":"kept","home_id":f.folder.as_str(),"reason":"seam test","idempotency_key":"seam-abandon"}),
            )
            .await,
        );
        tx.commit().await.unwrap();
        assert!(
            crate::kernel::read_record_as(&f.db, &f.owner_principal, &id)
                .await
                .unwrap()
                .is_some()
        );
        f.db.close().await;
    }

    /// Realtime stays silent while replay (and fold work) sits uncommitted in
    /// the outer transaction; it wakes once for the outer commit.
    #[tokio::test]
    async fn replay_does_not_wake_realtime_before_outer_commit() {
        let f = fixture(false).await;
        let actor = f.owner_principal.clone();
        let folder = f.folder.clone();
        let (db, hub) = RealtimeHub::install(f.db).await.unwrap();
        // Silence the install-time periodic tail tick (it also wakes): the
        // counter below must measure only wakes the commit path performs.
        // Terminalizing stops the pump and the tick; `wake` itself still
        // records, so the commit path stays observable.
        hub.terminalize();
        assert_eq!(hub.wake_calls_for_test(), 0);
        // Fold an empty accepted delta first (a no-op that still exercises
        // the whole fold and certification path), then replay the write.
        use crate::standby::kernel_v2_delta::{
            certify_fold_in_transaction, fold_in_transaction, ApplyMode,
        };
        use crate::standby::phase_timings::PhaseTimings;
        let delta = empty_delta_for(&db).await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let timings = PhaseTimings::default();
        let folded = fold_in_transaction(&mut tx, &delta, &timings, ApplyMode::Staged)
            .await
            .unwrap();
        let certified = certify_fold_in_transaction(&mut tx, &delta, folded, &timings)
            .await
            .unwrap();
        assert!(certified.receipt.is_none());
        let id = applied_id(
            replay_one(
                &db,
                &actor,
                &mut tx,
                "create_record",
                json!({"type":"Document","kind":"note","name":"quiet","body":"quiet","home_id":folder.as_str(),"reason":"seam test","idempotency_key":"seam-quiet"}),
            )
            .await,
        );
        assert_eq!(
            hub.wake_calls_for_test(),
            0,
            "replay and fold must not wake realtime before the outer commit"
        );
        db.commit_kernel_content(tx).await.unwrap();
        assert_eq!(
            hub.wake_calls_for_test(),
            1,
            "the outer commit wakes realtime exactly once through the commit path"
        );
        let record = crate::kernel::read_record_as(&db, &actor, &id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.body.as_deref(), Some("quiet"));
        db.close().await;
    }
}
