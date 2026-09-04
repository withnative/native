//! Backend-neutral domain transaction contracts.
//!
//! This module is deliberately not a repository or a storage API.  It owns the
//! semantic envelope that sits between canonical handlers and physical
//! transactions: normalized event payloads, deterministic projector intents,
//! stable operation/error names, and the small named ports which do not fit a
//! reviewed relational statement.
//!
//! SQLite continues to use its full projector. Every physical adapter must
//! consume the same [`ProjectorIntent`] and [`ProjectionPlan`] rather than
//! introducing a parallel domain model. Acquisition, write admission,
//! event-position allocation, commit, rollback, and realtime completion remain
//! backend-owned.

use futures::future::BoxFuture;
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::events::{
    CausalAdmission, EventRow, FacetSetPayload, FacetUnsetPayload, LinkAddedPayload,
    LinkRemovedPayload,
};
use crate::portable_sql::{ErrorCategory, ExecutionControl, ExecutionPhase, SqlError};
use crate::schema::{
    spine_facet_column, ARCHIVED_FACET_KEY, ENGINE_PROVISIONED_RECORD_IDS, ROOT_RECORD_ID,
    UNFILED_RECORD_ID,
};
use crate::{Error, Result};

#[cfg(any(feature = "postgres", feature = "turso-local"))]
#[path = "domain_transaction/logical_query.rs"]
pub(crate) mod logical_query;
#[path = "domain_transaction/record_shape_preflight.rs"]
mod record_shape_preflight;
#[path = "domain_transaction/request.rs"]
pub(crate) mod request;
#[cfg(any(feature = "postgres", feature = "turso-local"))]
#[path = "domain_transaction/search.rs"]
pub(crate) mod search;
#[path = "domain_transaction/transaction_lifecycle.rs"]
mod transaction_lifecycle;
#[cfg(any(feature = "postgres", feature = "turso-local"))]
#[path = "domain_transaction/views_history.rs"]
pub(crate) mod views_history;
pub(crate) use record_shape_preflight::execute_preview_record_shape;
pub(crate) use transaction_lifecycle::{
    run_backend_snapshot, run_backend_transaction, TransactionLifecyclePort,
};
#[cfg(feature = "turso-local")]
pub(crate) use transaction_lifecycle::{
    run_backend_transaction_with_disposition, TransactionDisposition,
};
#[path = "domain_transaction/facets.rs"]
mod facets;
pub(crate) use facets::{
    active_vocabulary_value, assert_open_facet_key, assert_required_not_worsened,
    assess_facet_write, classify_facet_key, facet_set_spec, govern_facet_writes,
    observation_write_response, parse_facet_write_value, required_violations,
    FacetKeyClassification, FacetPredicateAssessment, FacetWrite, RequiredViolation,
};
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) use facets::{
    execute_manage_facet_observations, execute_resolve_facets, execute_suggest_facet_values,
    FacetObservationPort,
};
#[path = "domain_transaction/attachments.rs"]
mod attachments;
#[cfg(any(feature = "postgres", feature = "turso-local"))]
#[path = "domain_transaction/identity_bindings.rs"]
mod identity_bindings;
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) use attachments::require_live_attachment_bearer;
pub(crate) use attachments::{
    create_attachment, detach_attachment, inspect_attachment, list_attachments, read_attachment,
    AttachmentCreate, AttachmentPhysicalPort,
};
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) use attachments::{prepare_attachment_detach, AttachmentDetachPreparation};
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) use identity_bindings::{
    manage_bindings, parse_manage_bindings, parse_resolve_external, resolve_external, BindingAudit,
    BindingPhysicalPort, BindingRow, BindingSystemRule,
};

/// Exact MCP-safe error for an operation that has not crossed conformance on
/// one backend. Backend adapters may retain diagnostics separately, but the
/// public error is intentionally bounded.
pub fn unsupported_backend_operation(backend: &str, operation: &str) -> Error {
    Error::engine(format!(
        "{backend} operation '{operation}' is unsupported by the qualified domain boundary"
    ))
}

/// Conservative member-facing history redaction shared by bounded adapters.
/// Identity-shaped values are never disclosed through event payloads. An
/// audience list retains only the caller's already-known account credential,
/// preventing one recipient from learning the other recipients.
#[cfg(any(test, feature = "postgres", feature = "turso-local"))]
pub(crate) fn redact_history_payload_for_member(payload: &mut Value, credential: &str) {
    let mut stack = vec![payload];
    while let Some(value) = stack.pop() {
        match value {
            Value::Object(object) => {
                for (key, child) in object.iter_mut() {
                    if key == "accounts" {
                        if let Value::Array(accounts) = child {
                            accounts.retain(|account| account.as_str() == Some(credential));
                        } else {
                            *child = Value::Null;
                        }
                    } else if matches!(
                        key.as_str(),
                        "actor" | "account_id" | "email" | "claimed_by_account" | "claimed_run_key"
                    ) || key == "id"
                        || key.ends_with("_id")
                        || matches!(key.as_str(), "owner" | "home")
                    {
                        *child = Value::Null;
                    } else {
                        stack.push(child);
                    }
                }
            }
            Value::Array(values) => stack.extend(values.iter_mut()),
            _ => {}
        }
    }
}

/// Convert storage-driver failures without exposing backend diagnostics to MCP
/// callers.  Protected evidence can retain [`SqlError::detail`] separately.
pub fn stable_storage_error(operation: &str, error: &SqlError) -> Error {
    Error::engine(format!("{operation}: {}", error.stable_message()))
}

/// Backend-owned event position allocation/append.  This is a named port
/// because sequence allocation and conflict policy are physical properties,
/// not portable SQL.
pub(crate) trait EventCursorPort {
    fn append_event<'a>(
        &'a mut self,
        event: &'a mut EventRow,
        causal_admission: &'a CausalAdmission,
        control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<i64>>;
}

/// Apply one already-parsed semantic intent inside the admitted transaction.
/// The shared planner decides containment and policy-anchor meaning; the
/// backend performs only its bounded state reads and physical writes.
pub(crate) trait ProjectorPort {
    fn apply_projector<'a>(
        &'a mut self,
        intent: &'a ProjectorIntent,
        event: &'a EventRow,
        control: &'a ExecutionControl,
    ) -> BoxFuture<'a, Result<()>>;
}

const RECORD_ID_MAX_BYTES: usize = 128;
const RECORD_ID_SHAPE_ERROR: &str =
    "record id must contain 1..=128 ASCII bytes using only [A-Za-z0-9._:-]";
const RECORD_ID_RESERVED_ERROR: &str =
    "record id prefix 'native:' is reserved for engine-owned records";
const RECORD_ID_UUID_ERROR: &str = "record id must be a canonical lowercase UUID of version 4 or 7";

/// A record id which is not one of the reserved `native:` constants must be a
/// canonical lowercase UUIDv4 or UUIDv7, and nothing else.
///
/// Only the two *random* versions are accepted. The deterministic versions —
/// v3 and v5 in particular — are excluded ON PURPOSE and must stay excluded: a
/// v5 is a hash of (namespace, name), so two databases deriving one from the
/// same business key mint the identical id. That is precisely the
/// cross-database collision this rule exists to prevent, so admitting v5
/// "because it is a valid UUID" would reopen the hole. v1/v6 are excluded for
/// the same family of reasons (node/time derived, not random).
fn accepted_uuid(record_id: &str) -> bool {
    let Ok(uuid) = Uuid::parse_str(record_id) else {
        return false;
    };
    matches!(
        uuid.get_version(),
        Some(uuid::Version::Random | uuid::Version::SortRand)
    )
        // Round-trip through the canonical hyphenated form so uppercase,
        // braced, and unhyphenated spellings are rejected here rather than by
        // a second, separately-drifting rule.
        && uuid.hyphenated().to_string() == record_id
}

/// TEMPORARY carve-out. The change-summary workflow derives its carrier record
/// id from a SHA-256 of `(audience_actor, workflow_key)`, and that SAME derived
/// string is the reuse lookup key: the workflow decides "have I already built
/// this?" with `SELECT EXISTS(... FROM records WHERE id=?)`. Randomising the id
/// without moving the reuse key first would silently mint a second carrier on
/// every call, so the UUID rule ships with this exemption instead of blocking
/// on that refactor.
///
/// The decision-consistent fix — filed as follow-up, not done here — is to
/// store an explicit idempotency key alongside the carrier and key reuse on
/// that column, leaving the record id a plain random UUID like every other
/// record's.
///
/// Do NOT widen this and do NOT copy the pattern. It accepts exactly one
/// literal prefix followed by exactly 64 lowercase hex characters, it is
/// reachable only from the change-summary carrier append, and it is the only
/// non-`native:` non-UUID id any authority may admit. Deriving a UUID from the
/// digest instead is expressly forbidden: that is UUIDv5 behaviour wearing a
/// v4's clothes, and two databases deriving from one business key would mint
/// the identical id — the exact cross-database collision the rule exists to
/// prevent.
const CHANGE_SUMMARY_CARRIER_PREFIX: &str = "change-summary:carrier:";

fn engine_derived_change_summary_carrier(record_id: &str) -> bool {
    let Some(digest) = record_id.strip_prefix(CHANGE_SUMMARY_CARRIER_PREFIX) else {
        return false;
    };
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[derive(Clone, Copy)]
enum RecordIdAuthority {
    CallerSupplied,
    Generated,
    EngineSeed,
    EngineProvisioning,
    /// See [`engine_derived_change_summary_carrier`]: temporary, narrow, and
    /// unreachable from any caller-facing surface.
    EngineDerived,
}

fn validate_record_id(record_id: &str, authority: RecordIdAuthority) -> Result<()> {
    let valid_shape = !record_id.is_empty()
        && record_id.len() <= RECORD_ID_MAX_BYTES
        && record_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if !valid_shape {
        return Err(Error::engine(RECORD_ID_SHAPE_ERROR));
    }
    match authority {
        RecordIdAuthority::CallerSupplied | RecordIdAuthority::Generated => {
            if record_id.starts_with("native:") {
                return Err(Error::engine(RECORD_ID_RESERVED_ERROR));
            }
            if !accepted_uuid(record_id) {
                return Err(Error::engine(RECORD_ID_UUID_ERROR));
            }
        }
        RecordIdAuthority::EngineSeed => {
            if !matches!(record_id, ROOT_RECORD_ID | UNFILED_RECORD_ID) {
                return Err(Error::engine(
                    "engine seed record id must be native:root or native:unfiled",
                ));
            }
        }
        RecordIdAuthority::EngineProvisioning => {
            if record_id.starts_with("native:") {
                if !ENGINE_PROVISIONED_RECORD_IDS.contains(&record_id) {
                    return Err(Error::engine(
                        "engine provisioning record id is not in the fixed allowlist",
                    ));
                }
            } else if !accepted_uuid(record_id) {
                // The non-reserved branch is unused today — every id reaching
                // `append_engine_provisioned_in` is one of the six reserved
                // constants — so this is a no-op in practice, kept so no
                // authority can mint a non-UUID id.
                return Err(Error::engine(RECORD_ID_UUID_ERROR));
            }
        }
        RecordIdAuthority::EngineDerived => {
            // Temporary change-summary carrier exemption; everything else,
            // including a `change-summary:series:` sibling or an uppercase
            // digest, still has to be a canonical random UUID.
            if !engine_derived_change_summary_carrier(record_id) && !accepted_uuid(record_id) {
                return Err(Error::engine(RECORD_ID_UUID_ERROR));
            }
        }
    }
    Ok(())
}

/// Resolve the optional public create id through the one record-id authority.
/// Explicit ids are caller-supplied; omitted ids are canonical UUIDv4 values
/// which still cross the same shape and namespace validation.
pub(crate) fn record_id_for_create(requested: Option<String>) -> Result<String> {
    match requested {
        Some(record_id) => {
            validate_record_id(&record_id, RecordIdAuthority::CallerSupplied)?;
            Ok(record_id)
        }
        None => {
            let record_id = Uuid::new_v4().to_string();
            validate_record_id(&record_id, RecordIdAuthority::Generated)?;
            Ok(record_id)
        }
    }
}

/// Shared append/project kernel.  It neither starts nor commits a transaction.
pub(crate) async fn append_and_project<T>(
    transaction: &mut T,
    event: &mut EventRow,
    control: &ExecutionControl,
) -> Result<ProjectorIntent>
where
    T: EventCursorPort + ProjectorPort,
{
    append_and_project_admitted(
        transaction,
        event,
        control,
        RecordIdAuthority::CallerSupplied,
        &CausalAdmission::LocalComputed,
    )
    .await
}

/// Narrow genesis-only admission for the two canonical filing records. The
/// capability is the call itself, not the actor string carried by the event.
pub(crate) async fn append_and_project_engine_seed<T>(
    transaction: &mut T,
    event: &mut EventRow,
    control: &ExecutionControl,
) -> Result<ProjectorIntent>
where
    T: EventCursorPort + ProjectorPort,
{
    if event.event_type != "record.created" {
        return Err(Error::engine(
            "engine seed admission accepts only record.created events",
        ));
    }
    append_and_project_admitted(
        transaction,
        event,
        control,
        RecordIdAuthority::EngineSeed,
        &CausalAdmission::LocalComputed,
    )
    .await
}

/// Admission for the sealed instruction provisioning workflow. Ordinary ids
/// (including its freshly generated personal-context UUIDs) retain the public
/// shape contract; only the fixed product instruction ids may cross into the
/// reserved namespace.
pub(crate) async fn append_and_project_engine_provisioned<T>(
    transaction: &mut T,
    event: &mut EventRow,
    control: &ExecutionControl,
) -> Result<ProjectorIntent>
where
    T: EventCursorPort + ProjectorPort,
{
    if event.event_type != "record.created" {
        return Err(Error::engine(
            "engine provisioning admission accepts only record.created events",
        ));
    }
    append_and_project_admitted(
        transaction,
        event,
        control,
        RecordIdAuthority::EngineProvisioning,
        &CausalAdmission::LocalComputed,
    )
    .await
}

/// Admission for the change-summary carrier alone. It exists only so the
/// temporary derived-id exemption has one named, greppable caller instead of
/// being smuggled through the ordinary append path — see
/// [`engine_derived_change_summary_carrier`] for why the exemption exists and
/// why it must not be widened.
pub(crate) async fn append_and_project_engine_derived<T>(
    transaction: &mut T,
    event: &mut EventRow,
    control: &ExecutionControl,
) -> Result<ProjectorIntent>
where
    T: EventCursorPort + ProjectorPort,
{
    if event.event_type != "record.created" {
        return Err(Error::engine(
            "engine derived admission accepts only record.created events",
        ));
    }
    append_and_project_admitted(
        transaction,
        event,
        control,
        RecordIdAuthority::EngineDerived,
        &CausalAdmission::LocalComputed,
    )
    .await
}

/// Sealed import admission. The verified source envelope is preserved exactly;
/// ordinary append callers cannot reach this function through `AppendSpec`.
pub(crate) async fn append_and_project_governed_import<T>(
    transaction: &mut T,
    event: &mut EventRow,
    causal_admission: &CausalAdmission,
    control: &ExecutionControl,
) -> Result<ProjectorIntent>
where
    T: EventCursorPort + ProjectorPort,
{
    if !matches!(causal_admission, CausalAdmission::GovernedImport(_)) {
        return Err(Error::engine(
            "governed import append requires governed causal admission",
        ));
    }
    append_and_project_admitted(
        transaction,
        event,
        control,
        RecordIdAuthority::CallerSupplied,
        causal_admission,
    )
    .await
}

async fn append_and_project_admitted<T>(
    transaction: &mut T,
    event: &mut EventRow,
    control: &ExecutionControl,
    authority: RecordIdAuthority,
    causal_admission: &CausalAdmission,
) -> Result<ProjectorIntent>
where
    T: EventCursorPort + ProjectorPort,
{
    if event.event_type == "record.created" {
        validate_record_id(&event.record_id, authority)?;
    }
    let intent = ProjectorIntent::from_event(event)?;
    event.local_seq = transaction
        .append_event(event, causal_admission, control)
        .await?;
    event.causal_envelope.validate_for_event(&event.id)?;
    transaction.apply_projector(&intent, event, control).await?;
    Ok(intent)
}

/// Typed semantic intent produced before either physical projector runs.
///
/// The seven variants are the complete canonical slice owned here.  Other
/// already-supported SQLite event families remain represented as `Extended`;
/// this preserves SQLite behaviour while making a Turso attempt fail closed by
/// exact event name rather than silently inventing a projection.
#[derive(Debug, Clone)]
pub enum ProjectorIntent {
    RecordCreated(Map<String, Value>),
    RecordUpdated(Map<String, Value>),
    RecordTypeCorrected(crate::events::RecordTypeCorrectedPayload),
    RecordDeleted,
    FacetSet(FacetSetPayload),
    FacetUnset(FacetUnsetPayload),
    LinkAdded(LinkAddedPayload),
    LinkRemoved(LinkRemovedPayload),
    Extended { event_type: String, payload: Value },
}

impl ProjectorIntent {
    /// Parse and validate event meaning once, before backend-specific SQL.
    pub fn from_event(event: &EventRow) -> Result<Self> {
        let payload = event
            .payload
            .as_deref()
            .ok_or_else(|| {
                Error::engine(format!(
                    "event {} ({}) has no payload",
                    event.id, event.event_type
                ))
            })
            .and_then(|payload| serde_json::from_str::<Value>(payload).map_err(Error::from))?;
        match event.event_type.as_str() {
            "record.created" => {
                let fields = object_payload(event, payload)?;
                required_kind(event, fields.get("kind"))?;
                Ok(Self::RecordCreated(fields))
            }
            "record.updated" => {
                let fields = object_payload(event, payload)?;
                Ok(Self::RecordUpdated(fields))
            }
            "record.type_corrected.v1" => {
                Ok(Self::RecordTypeCorrected(serde_json::from_value(payload)?))
            }
            "record.deleted" => {
                object_payload(event, payload)?;
                Ok(Self::RecordDeleted)
            }
            "facet.set" => Ok(Self::FacetSet(serde_json::from_value(payload)?)),
            "facet.unset" => Ok(Self::FacetUnset(serde_json::from_value(payload)?)),
            "link.added" => {
                let link: LinkAddedPayload = serde_json::from_value(payload)?;
                validate_link_envelope(
                    event,
                    &link.source_id,
                    &link.target_id,
                    &link.relationship,
                )?;
                Ok(Self::LinkAdded(link))
            }
            "link.removed" => {
                let link: LinkRemovedPayload = serde_json::from_value(payload)?;
                validate_link_envelope(
                    event,
                    &link.source_id,
                    &link.target_id,
                    &link.relationship,
                )?;
                Ok(Self::LinkRemoved(link))
            }
            event_type if crate::events::EVENT_TYPES.contains(&event_type) => Ok(Self::Extended {
                event_type: event_type.to_string(),
                payload,
            }),
            other => Err(Error::engine(format!("unknown event type: {other}"))),
        }
    }

    pub fn event_type(&self) -> &str {
        match self {
            Self::RecordCreated(_) => "record.created",
            Self::RecordUpdated(_) => "record.updated",
            Self::RecordTypeCorrected(_) => "record.type_corrected.v1",
            Self::RecordDeleted => "record.deleted",
            Self::FacetSet(_) => "facet.set",
            Self::FacetUnset(_) => "facet.unset",
            Self::LinkAdded(_) => "link.added",
            Self::LinkRemoved(_) => "link.removed",
            Self::Extended { event_type, .. } => event_type,
        }
    }
}

/// The semantic state the canonical content fold may inspect. Drivers can
/// obtain it however they need to, but cannot add backend-specific meaning to
/// the seven canonical event families.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordSemanticState {
    pub record_type: String,
    pub kind: Option<String>,
    pub persistence: String,
    pub deleted: bool,
    pub policy_anchor_id: Option<String>,
    pub archived: bool,
    pub targeted: bool,
    pub attributed: bool,
    pub semantic_unit: bool,
    pub message_status: Option<String>,
}

/// Narrow state reads needed to decide canonical content meaning. Projection
/// writes, event allocation and policy-anchor refresh are deliberately not
/// hidden behind a general repository interface.
pub(crate) trait ContentSemanticStatePort {
    fn record_state<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<RecordSemanticState>>>;

    fn home_would_cycle<'a>(
        &'a mut self,
        record_id: &'a str,
        home_id: &'a str,
    ) -> BoxFuture<'a, Result<bool>>;

    fn first_live_child<'a>(
        &'a mut self,
        record_id: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>>;

    fn link_identity<'a>(
        &'a mut self,
        source_id: &'a str,
        target_id: &'a str,
        relationship: &'a str,
    ) -> BoxFuture<'a, Result<Option<String>>>;
}

#[derive(Debug, Clone)]
pub(crate) enum RecordFieldUpdate {
    Kind(Value),
    Name(Value),
    Body(Value),
    HomeId(Value),
    Lifecycle(Value),
    OwnerId(Value),
    Persistence(Value),
    Maturity(Value),
    Summary(Value),
    ClaimedByAccount(Value),
    ClaimedRunKey(Value),
    ClaimedAt(Value),
}

/// Everything a substrate needs in order to write one `records` column, in the
/// two spellings the two substrates use.
///
/// Both are `&'static str`: no adapter builds column text at runtime, so no
/// caller-controlled text can reach a statement, and the portable template
/// contract's `&'static` fragment requirement is satisfied without leaking.
pub(crate) struct RecordColumnWrite<'a> {
    /// SQLite `SET` assignment naming exactly this one column.
    pub assignment: &'static str,
    /// Portable single-column update template fragments: the value, then the
    /// record id. Gated with its only consumer so the default build does not
    /// carry a field nothing reads.
    #[cfg(feature = "turso-local")]
    pub portable_update: &'static [&'static str],
    pub value: &'a Value,
}

impl RecordFieldUpdate {
    /// The one place a field is mapped to the column it writes.
    ///
    /// This deliberately replaces the parallel arrays each substrate used to
    /// keep — a positional slot list beside a positional column list, whose
    /// agreement no compiler checked. Adding a variant now fails to compile
    /// until both spellings are supplied, and a mid-list insertion cannot
    /// silently write one field's value into another field's column.
    ///
    /// Callers may assume at most one write per column: `RecordFieldUpdate`
    /// lists are built from a JSON object's distinct keys, and the three claim
    /// fields are disjoint from those.
    pub(crate) fn write(&self) -> RecordColumnWrite<'_> {
        macro_rules! write_for {
            ($column:literal, $value:expr) => {
                RecordColumnWrite {
                    assignment: concat!($column, "=?"),
                    #[cfg(feature = "turso-local")]
                    portable_update: &[
                        concat!("UPDATE {{relation}} SET ", $column, "="),
                        " WHERE id=",
                        "",
                    ],
                    value: $value,
                }
            };
        }
        match self {
            Self::Kind(value) => write_for!("kind", value),
            Self::Name(value) => write_for!("name", value),
            Self::Body(value) => write_for!("body", value),
            Self::HomeId(value) => write_for!("home_id", value),
            Self::Lifecycle(value) => write_for!("lifecycle", value),
            Self::OwnerId(value) => write_for!("owner_id", value),
            Self::Persistence(value) => write_for!("persistence", value),
            Self::Maturity(value) => write_for!("maturity", value),
            Self::Summary(value) => write_for!("summary", value),
            Self::ClaimedByAccount(value) => write_for!("claimed_by_account", value),
            Self::ClaimedRunKey(value) => write_for!("claimed_run_key", value),
            Self::ClaimedAt(value) => write_for!("claimed_at", value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpineFacet {
    Lifecycle,
    Owner,
    Persistence,
    Maturity,
}

#[derive(Debug, Clone)]
pub(crate) struct MessageMention {
    pub mention_id: String,
    pub target_kind: String,
    pub target_binding: String,
    pub target_record_id: String,
    pub span_start: i64,
    pub span_end: i64,
    pub authored_label: String,
}

/// A fully validated, deterministic projection operation. Once this value
/// exists, a backend may only perform the corresponding physical writes.
#[derive(Debug, Clone)]
pub(crate) enum ProjectionPlan {
    RecordCreated {
        fields: Map<String, Value>,
        kind: String,
        policy_anchor_id: String,
        message_mentions: Option<Vec<MessageMention>>,
    },
    RecordUpdated {
        fields: Vec<RecordFieldUpdate>,
        refresh_policy_anchor: bool,
    },
    RecordTypeCorrected {
        record_type: String,
        kind: String,
    },
    RecordDeleted,
    FacetSet {
        payload: FacetSetPayload,
        spine: Option<SpineFacet>,
    },
    FacetUnset {
        payload: FacetUnsetPayload,
        spine: Option<SpineFacet>,
    },
    LinkAdded {
        payload: LinkAddedPayload,
        link_id: String,
        relationship_owned: bool,
    },
    LinkRemoved {
        payload: LinkRemovedPayload,
        relationship_owned: bool,
    },
}

/// Resolve canonical event meaning against the minimum required current state.
/// No physical projection write is allowed before this returns successfully.
pub(crate) async fn plan_projection<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    intent: &ProjectorIntent,
) -> Result<ProjectionPlan> {
    match intent {
        ProjectorIntent::RecordCreated(fields) => {
            plan_record_created(state, event, fields.clone()).await
        }
        ProjectorIntent::RecordUpdated(fields) => {
            plan_record_updated(state, event, fields.clone()).await
        }
        ProjectorIntent::RecordTypeCorrected(payload) => {
            plan_record_type_corrected(state, event, payload).await
        }
        ProjectorIntent::RecordDeleted => {
            let current = live_record(state, &event.record_id, &event.event_type).await?;
            if event.record_id == ROOT_RECORD_ID || event.record_id == UNFILED_RECORD_ID {
                return Err(Error::engine(format!(
                    "cannot apply record.deleted: engine filing record {} cannot be removed",
                    event.record_id
                )));
            }
            if current.record_type == "Annotation" && current.kind.as_deref() == Some("attribution")
            {
                return Err(Error::engine(format!(
                    "cannot delete attribution {}: append attribution.retracted.v1 for an erroneous claim",
                    event.record_id
                )));
            }
            assert_no_live_children(state, &event.record_id, &event.event_type).await?;
            Ok(ProjectionPlan::RecordDeleted)
        }
        ProjectorIntent::FacetSet(payload) => plan_facet_set(state, event, payload.clone()).await,
        ProjectorIntent::FacetUnset(payload) => {
            plan_facet_unset(state, event, payload.clone()).await
        }
        ProjectorIntent::LinkAdded(payload) => plan_link_added(state, event, payload.clone()).await,
        ProjectorIntent::LinkRemoved(payload) => {
            plan_link_removed(state, event, payload.clone()).await
        }
        ProjectorIntent::Extended { event_type, .. } => Err(Error::engine(format!(
            "event {event_type} is outside the canonical content projection slice"
        ))),
    }
}

async fn plan_record_type_corrected<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    payload: &crate::events::RecordTypeCorrectedPayload,
) -> Result<ProjectionPlan> {
    use crate::events::RecordTypeCorrectionMode;

    let current = live_record(state, &event.record_id, &event.event_type).await?;
    if current.record_type != payload.from.record_type
        || current.kind.as_deref() != Some(payload.from.kind.as_str())
    {
        return Err(Error::engine(format!(
            "cannot apply record.type_corrected.v1: record {} no longer matches from identity {}/{}",
            event.record_id, payload.from.record_type, payload.from.kind
        )));
    }
    if payload.from == payload.to {
        return Err(Error::engine(
            "cannot apply record.type_corrected.v1: from and to identities are identical",
        ));
    }
    if !crate::schema::SPINE_TYPES.contains(&payload.to.record_type.as_str())
        || payload.to.kind.trim().is_empty()
    {
        return Err(Error::engine(
            "cannot apply record.type_corrected.v1: target requires a closed spine type and non-empty kind",
        ));
    }
    if payload.reason.trim().is_empty()
        || payload.plan_id.trim().is_empty()
        || payload.schema_state_revision.trim().is_empty()
        || !payload.effect_digest.starts_with("sha256:")
        || payload.effect_digest.len() != 71
        || !payload.effect_digest[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Error::engine(
            "cannot apply record.type_corrected.v1: invalid governed plan evidence",
        ));
    }
    if matches!(payload.mode, RecordTypeCorrectionMode::Confirmed) != payload.confirmation_required
    {
        return Err(Error::engine(
            "cannot apply record.type_corrected.v1: mode and confirmation_required disagree",
        ));
    }
    if event.record_id == ROOT_RECORD_ID || event.record_id == UNFILED_RECORD_ID {
        return Err(Error::engine(format!(
            "cannot apply record.type_corrected.v1: engine filing record {} has immutable identity",
            event.record_id
        )));
    }
    if current.semantic_unit {
        return Err(Error::engine(format!(
            "cannot apply record.type_corrected.v1: semantic Unit {} has immutable identity",
            event.record_id
        )));
    }
    if current.targeted {
        return Err(Error::engine(format!(
            "cannot apply record.type_corrected.v1: targeted Annotation {} has immutable identity",
            event.record_id
        )));
    }
    if current.attributed
        || (current.record_type == "Annotation" && current.kind.as_deref() == Some("attribution"))
        || (payload.to.record_type == "Annotation" && payload.to.kind == "attribution")
    {
        return Err(Error::engine(format!(
            "cannot apply record.type_corrected.v1: governed attribution {} has immutable identity",
            event.record_id
        )));
    }
    if current.record_type == "Message"
        && current.message_status.as_deref() != Some("pending_local")
    {
        return Err(Error::engine(format!(
            "cannot apply record.type_corrected.v1: Message {} has non-local delivery state",
            event.record_id
        )));
    }
    if payload.to.record_type == "Message" {
        return Err(Error::engine(
            "cannot apply record.type_corrected.v1: Message identity must be created atomically with its audience state",
        ));
    }
    if payload.to.record_type == "Annotation"
        && matches!(payload.to.kind.as_str(), "citation" | "comment")
    {
        return Err(Error::engine(
            "cannot apply record.type_corrected.v1: targeted Annotation identity must be created atomically with its target",
        ));
    }

    Ok(ProjectionPlan::RecordTypeCorrected {
        record_type: payload.to.record_type.clone(),
        kind: payload.to.kind.clone(),
    })
}

async fn plan_record_created<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    fields: Map<String, Value>,
) -> Result<ProjectionPlan> {
    let kind = required_kind(event, fields.get("kind"))?.to_string();
    let home_id = fields.get("home_id").and_then(Value::as_str);
    let policy_anchor_id = if event.record_id == ROOT_RECORD_ID {
        if home_id.is_some()
            || fields.get("type").and_then(Value::as_str) != Some("Collection")
            || fields.get("kind").and_then(Value::as_str) != Some("folder")
            || fields.get("persistence").and_then(Value::as_str) != Some("enduring")
        {
            return Err(Error::engine(
                "cannot create canonical root: native:root must be an enduring Collection kind:folder with home_id null",
            ));
        }
        event.record_id.clone()
    } else {
        if event.record_id == UNFILED_RECORD_ID
            && (home_id != Some(ROOT_RECORD_ID)
                || fields.get("type").and_then(Value::as_str) != Some("Collection")
                || fields.get("kind").and_then(Value::as_str) != Some("folder")
                || fields.get("persistence").and_then(Value::as_str) != Some("enduring"))
        {
            return Err(Error::engine(
                "cannot create canonical Unfiled: native:unfiled must be an enduring Collection kind:folder with home_id native:root",
            ));
        }
        let home_id = home_id.ok_or_else(|| {
            Error::engine(format!(
                "cannot apply record.created: record {} requires a non-null home_id",
                event.record_id
            ))
        })?;
        let home = valid_home(state, &event.record_id, home_id, &event.event_type).await?;
        home.policy_anchor_id.ok_or_else(|| {
            Error::engine(format!(
                "cannot create record {}: its home has no effective policy anchor",
                event.record_id
            ))
        })?
    };

    let message_mentions = if fields.get("type").and_then(Value::as_str) == Some("Message") {
        let mentions = fields
            .get("mentions")
            .and_then(Value::as_array)
            .map(|mentions| mentions.iter().map(parse_message_mention).collect())
            .transpose()?
            .unwrap_or_default();
        Some(mentions)
    } else {
        None
    };
    Ok(ProjectionPlan::RecordCreated {
        fields,
        kind,
        policy_anchor_id,
        message_mentions,
    })
}

async fn plan_record_updated<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    fields: Map<String, Value>,
) -> Result<ProjectionPlan> {
    let current = live_record(state, &event.record_id, &event.event_type).await?;
    if current.semantic_unit
        && (fields.contains_key("body")
            || fields.contains_key("kind")
            || fields.contains_key("type"))
    {
        return if fields.contains_key("body") {
            Err(Error::engine(format!(
                "cannot apply record.updated to Unit {}: body changes require unit.revision.recorded.v1",
                event.record_id
            )))
        } else {
            Err(Error::engine(format!(
                "cannot change Unit {} identity envelope through record.updated",
                event.record_id
            )))
        };
    }
    if current.record_type == "Message"
        && current.message_status.as_deref() != Some("pending_local")
    {
        let immutable: Vec<&str> = ["name", "body", "kind", "owner_id"]
            .into_iter()
            .filter(|key| fields.contains_key(*key))
            .collect();
        if !immutable.is_empty() {
            return Err(Error::engine(format!(
                "Message fields {} are immutable creation content; create a superseding Message",
                immutable.join(", ")
            )));
        }
    }
    if fields.contains_key("type") {
        return Err(Error::engine(format!(
            "cannot apply record.updated to {}: `type` is immutable — a record keeps its spine type for life (2e5ed3e; F6a of 6285fa8). There is no cross-type promotion path: create the correctly-typed record and re-link.",
            event.record_id
        )));
    }
    if fields.contains_key("kind") {
        required_kind(event, fields.get("kind"))?;
    }
    if event.record_id == ROOT_RECORD_ID || event.record_id == UNFILED_RECORD_ID {
        // `name` is deliberately absent from this list, and must stay absent.
        // The root record IS the workspace, and its name is display-only: no
        // handle, slug, URL, or identifier is derived from it, so relabelling
        // it is a presentation change with no downstream consequence. The
        // structural facts below are what the engine relies on, and those are
        // frozen for life. Who may perform the rename is a separate question,
        // answered at the tool surface (`update_record`), because the projector
        // has no caller.
        for protected in ["kind", "home_id", "persistence"] {
            if fields.contains_key(protected) {
                return Err(Error::engine(format!(
                    "cannot apply record.updated: engine filing record {} has immutable {protected}",
                    event.record_id
                )));
            }
        }
    }
    if let Some(home) = fields.get("home_id") {
        let home = home.as_str().ok_or_else(|| {
            Error::engine(format!(
                "cannot apply record.updated: record {} requires a non-null home_id",
                event.record_id
            ))
        })?;
        valid_home(state, &event.record_id, home, &event.event_type).await?;
    }
    let resulting_kind = fields
        .get("kind")
        .and_then(Value::as_str)
        .or(current.kind.as_deref());
    let resulting_persistence = fields
        .get("persistence")
        .and_then(Value::as_str)
        .unwrap_or(&current.persistence);
    let was_folder =
        current.record_type == "Collection" && current.kind.as_deref() == Some("folder");
    let remains_valid_folder = current.record_type == "Collection"
        && resulting_kind == Some("folder")
        && resulting_persistence == "enduring";
    if was_folder && !remains_valid_folder {
        assert_no_live_children(state, &event.record_id, &event.event_type).await?;
    }
    if current.targeted
        && (current.record_type != "Annotation"
            || !matches!(current.kind.as_deref(), Some("citation" | "comment"))
            || resulting_kind != current.kind.as_deref())
    {
        return Err(Error::engine(format!(
            "cannot apply record.updated to targeted Annotation {}: it must retain its target-bearing Annotation kind; remove its annotation target first",
            event.record_id
        )));
    }
    if current.record_type == "Annotation"
        && current.kind.as_deref() == Some("attribution")
        && fields.contains_key("kind")
        && fields.get("kind").and_then(Value::as_str) != current.kind.as_deref()
    {
        return Err(Error::engine(format!(
            "cannot change governed attribution {} identity; create a successor attribution instead",
            event.record_id
        )));
    }
    // Supported writes canonicalize governed aliases before appending content
    // events. The shared content planner is intentionally meta-tier agnostic,
    // so the raw direct/replay boundary enforces the canonical comment token.
    if current.record_type == "Annotation"
        && resulting_kind == Some("comment")
        && current.kind.as_deref() != Some("comment")
    {
        return Err(Error::engine(format!(
            "cannot apply record.updated to {}: comment identity must be created atomically with its bearer",
            event.record_id
        )));
    }
    let claim_touched = fields.contains_key("claimed_by_account")
        || fields.contains_key("claimed_run_key")
        || fields.contains_key("claimed_at");
    let claim_update = if claim_touched {
        if fields.contains_key("claimed_at") {
            return Err(Error::engine(
                "cannot apply record.updated: claimed_at is derived from the event timestamp",
            ));
        }
        let account = fields.get("claimed_by_account").ok_or_else(|| {
            Error::engine(
                "cannot apply record.updated: claim projection requires claimed_by_account",
            )
        })?;
        let run_key = fields.get("claimed_run_key").ok_or_else(|| {
            Error::engine("cannot apply record.updated: claim projection requires claimed_run_key")
        })?;
        match account {
            Value::String(value) if !value.trim().is_empty() => {}
            Value::Null if run_key.is_null() => {}
            Value::Null => {
                return Err(Error::engine(
                    "cannot apply record.updated: an unclaimed record cannot retain a run key",
                ))
            }
            _ => {
                return Err(Error::engine(
                    "cannot apply record.updated: claimed_by_account must be a non-blank string or null",
                ))
            }
        }
        if !(matches!(run_key, Value::String(value) if !value.is_empty()) || run_key.is_null()) {
            return Err(Error::engine(
                "cannot apply record.updated: claimed_run_key must be a non-empty string or null",
            ));
        }
        Some((
            account.clone(),
            run_key.clone(),
            if account.is_null() {
                Value::Null
            } else {
                Value::String(event.created_at.clone())
            },
        ))
    } else {
        None
    };
    let mut updates = Vec::new();
    for (key, value) in fields {
        let update = match key.as_str() {
            "kind" => Some(RecordFieldUpdate::Kind(value)),
            "name" => Some(RecordFieldUpdate::Name(value)),
            "body" => Some(RecordFieldUpdate::Body(value)),
            "home_id" => Some(RecordFieldUpdate::HomeId(value)),
            "lifecycle" => Some(RecordFieldUpdate::Lifecycle(value)),
            "owner_id" => Some(RecordFieldUpdate::OwnerId(value)),
            "persistence" => Some(RecordFieldUpdate::Persistence(value)),
            "maturity" => Some(RecordFieldUpdate::Maturity(value)),
            "summary" => Some(RecordFieldUpdate::Summary(value)),
            "claimed_by_account" | "claimed_run_key" | "claimed_at" => None,
            _ => None,
        };
        if let Some(update) = update {
            updates.push(update);
        }
    }
    if let Some((account, run_key, claimed_at)) = claim_update {
        updates.push(RecordFieldUpdate::ClaimedByAccount(account));
        updates.push(RecordFieldUpdate::ClaimedRunKey(run_key));
        updates.push(RecordFieldUpdate::ClaimedAt(claimed_at));
    }
    Ok(ProjectionPlan::RecordUpdated {
        refresh_policy_anchor: updates
            .iter()
            .any(|field| matches!(field, RecordFieldUpdate::HomeId(_))),
        fields: updates,
    })
}

async fn plan_facet_set<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    payload: FacetSetPayload,
) -> Result<ProjectionPlan> {
    let current = live_record(state, &event.record_id, &event.event_type).await?;
    if payload.key == crate::message_expectation::EXPECTATION_FACET_KEY
        && current.record_type == "Message"
        && current.message_status.as_deref() != Some("pending_local")
    {
        return Err(Error::engine(
            "Message expectation is immutable sender-authored content; create a superseding Message",
        ));
    }
    if payload.key == ARCHIVED_FACET_KEY {
        if event.record_id == ROOT_RECORD_ID || event.record_id == UNFILED_RECORD_ID {
            return Err(Error::engine(format!(
                "engine filing record {} cannot be archived",
                event.record_id
            )));
        }
        assert_no_live_children(state, &event.record_id, &event.event_type).await?;
        if payload.value.as_deref() != Some("true") {
            return Err(Error::engine(format!(
                "engine-reserved facet '{ARCHIVED_FACET_KEY}' only takes the value 'true' — restore by unsetting the facet, not by writing another value"
            )));
        }
    }
    if payload.key == "persistence" {
        if event.record_id == ROOT_RECORD_ID || event.record_id == UNFILED_RECORD_ID {
            return Err(Error::engine(format!(
                "cannot apply facet.set: engine filing record {} has immutable persistence",
                event.record_id
            )));
        }
        if current.record_type == "Collection"
            && current.kind.as_deref() == Some("folder")
            && payload.value.as_deref() != Some("enduring")
        {
            assert_no_live_children(state, &event.record_id, &event.event_type).await?;
        }
    }
    let spine = spine_facet(&payload.key);
    if payload.observation_only && spine.is_some() {
        return Err(Error::engine(format!(
            "cannot project observation-only facet.set for spine facet '{}'",
            payload.key
        )));
    }
    Ok(ProjectionPlan::FacetSet { payload, spine })
}

async fn plan_facet_unset<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    payload: FacetUnsetPayload,
) -> Result<ProjectionPlan> {
    let current = live_record(state, &event.record_id, &event.event_type).await?;
    if payload.key == crate::message_expectation::EXPECTATION_FACET_KEY
        && current.record_type == "Message"
    {
        return Err(Error::engine(
            "Message expectation is immutable sender-authored content; create a superseding Message",
        ));
    }
    if payload.key == "persistence" {
        return Err(Error::engine(
            "cannot unset persistence: it is a required spine facet (set enduring|occurrent)",
        ));
    }
    let spine = spine_facet(&payload.key);
    if payload.observation_only && spine.is_some() {
        return Err(Error::engine(format!(
            "cannot project observation-only facet.unset for spine facet '{}'",
            payload.key
        )));
    }
    Ok(ProjectionPlan::FacetUnset { payload, spine })
}

async fn plan_link_added<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    payload: LinkAddedPayload,
) -> Result<ProjectionPlan> {
    let source = live_record(state, &payload.source_id, &event.event_type).await?;
    let target = live_record(state, &payload.target_id, &event.event_type).await?;
    if source.record_type == "Annotation"
        && source.kind.as_deref() == Some("attribution")
        && source.attributed
        && matches!(payload.relationship.as_str(), "part_of" | "supersedes")
    {
        return Err(Error::engine(
            "an attribution's bearer and successor links are immutable; create a successor aggregate",
        ));
    }
    validate_message_link(&source, &payload.relationship, false)?;
    if payload.relationship == "participates_in"
        && (source.record_type != "Message" || target.record_type != "Conversation")
    {
        return Err(Error::engine(
            "participates_in requires a Message source and Conversation target",
        ));
    }
    if payload.relationship == "supersedes"
        && source.record_type == "Message"
        && target.record_type != "Message"
    {
        return Err(Error::engine("supersedes requires Message endpoints"));
    }
    let link_id = payload.id.clone().unwrap_or_else(|| {
        format!(
            "lnk:{}:{}:{}",
            payload.source_id, payload.target_id, payload.relationship
        )
    });
    let relationship_owned = crate::relationship::legacy::classify(
        Some(&source.record_type),
        Some(&target.record_type),
        payload.id.as_deref(),
        &payload.relationship,
    ) == crate::relationship::legacy::LinkOwnership::Relationship;
    Ok(ProjectionPlan::LinkAdded {
        payload,
        link_id,
        relationship_owned,
    })
}

async fn plan_link_removed<S: ContentSemanticStatePort>(
    state: &mut S,
    event: &EventRow,
    payload: LinkRemovedPayload,
) -> Result<ProjectionPlan> {
    let source = live_record(state, &payload.source_id, &event.event_type).await?;
    let target = live_record(state, &payload.target_id, &event.event_type).await?;
    validate_message_link(&source, &payload.relationship, true)?;
    if source.record_type == "Annotation"
        && source.kind.as_deref() == Some("attribution")
        && matches!(payload.relationship.as_str(), "part_of" | "supersedes")
    {
        return Err(Error::engine(
            "an attribution's bearer and successor links are immutable",
        ));
    }
    let link_id = state
        .link_identity(
            &payload.source_id,
            &payload.target_id,
            &payload.relationship,
        )
        .await?;
    let relationship_owned = crate::relationship::legacy::classify(
        Some(&source.record_type),
        Some(&target.record_type),
        link_id.as_deref(),
        &payload.relationship,
    ) == crate::relationship::legacy::LinkOwnership::Relationship;
    Ok(ProjectionPlan::LinkRemoved {
        payload,
        relationship_owned,
    })
}

fn validate_message_link(
    source: &RecordSemanticState,
    relationship: &str,
    removing: bool,
) -> Result<()> {
    if source.record_type == "Message"
        && matches!(relationship, "addressed_to" | "reply_to" | "supersedes")
        && source.message_status.as_deref() != Some("pending_local")
    {
        let replacement = if removing { "a superseding" } else { "a new" };
        return Err(Error::engine(format!(
            "{relationship} is immutable Message content; create {replacement} Message instead"
        )));
    }
    Ok(())
}

async fn live_record<S: ContentSemanticStatePort>(
    state: &mut S,
    record_id: &str,
    event_type: &str,
) -> Result<RecordSemanticState> {
    let Some(record) = state.record_state(record_id).await? else {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {record_id} does not exist"
        )));
    };
    if record.deleted {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {record_id} is deleted (tombstoned)"
        )));
    }
    Ok(record)
}

async fn valid_home<S: ContentSemanticStatePort>(
    state: &mut S,
    record_id: &str,
    home_id: &str,
    event_type: &str,
) -> Result<RecordSemanticState> {
    if record_id == home_id {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: record {record_id} cannot be its own home"
        )));
    }
    let Some(home) = state.record_state(home_id).await? else {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: home {home_id} does not exist"
        )));
    };
    if home.record_type != "Collection"
        || home.kind.as_deref() != Some("folder")
        || home.persistence != "enduring"
        || home.deleted
        || home.archived
    {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: home {home_id} must be a live, unarchived, enduring Collection kind:folder"
        )));
    }
    if state.home_would_cycle(record_id, home_id).await? {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: homing {record_id} in {home_id} would create a cycle"
        )));
    }
    Ok(home)
}

async fn assert_no_live_children<S: ContentSemanticStatePort>(
    state: &mut S,
    record_id: &str,
    event_type: &str,
) -> Result<()> {
    if let Some(child) = state.first_live_child(record_id).await? {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: folder {record_id} still has live homed members (including {child}); rehome its members atomically first"
        )));
    }
    Ok(())
}

fn spine_facet(key: &str) -> Option<SpineFacet> {
    debug_assert_eq!(
        spine_facet_column(key).is_some(),
        matches!(key, "lifecycle" | "owner" | "persistence" | "maturity")
    );
    match key {
        "lifecycle" => Some(SpineFacet::Lifecycle),
        "owner" => Some(SpineFacet::Owner),
        "persistence" => Some(SpineFacet::Persistence),
        "maturity" => Some(SpineFacet::Maturity),
        _ => None,
    }
}

fn parse_message_mention(value: &Value) -> Result<MessageMention> {
    let object = value
        .as_object()
        .ok_or_else(|| Error::engine("Message mention declaration must be an object"))?;
    Ok(MessageMention {
        mention_id: mention_string(object, "mention_id", "Message mention id is invalid")?,
        target_kind: mention_string(
            object,
            "target_kind",
            "Message mention target kind is invalid",
        )?,
        target_binding: mention_string(
            object,
            "target_binding",
            "Message mention binding is invalid",
        )?,
        target_record_id: mention_string(object, "target_id", "Message mention target is invalid")?,
        span_start: object
            .get("span_start")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::engine("Message mention span is invalid"))?
            as i64,
        span_end: object
            .get("span_end")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::engine("Message mention span is invalid"))?
            as i64,
        authored_label: mention_string(
            object,
            "authored_label",
            "Message mention label is invalid",
        )?,
    })
}

fn mention_string(object: &Map<String, Value>, key: &str, error: &str) -> Result<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| Error::engine(error))
}

/// Canonical payload normalization shared by every event producer.
///
/// Placement omission has one meaning on every backend: non-root records are
/// homed in Unfiled.  Keeping this outside an adapter prevents replay from
/// changing meaning when a driver changes.
pub fn normalize_event_payload(record_id: &str, event_type: &str, payload: Value) -> Value {
    let mut payload = if payload.is_null() {
        json!({})
    } else {
        payload
    };
    if event_type == "record.created" && record_id != ROOT_RECORD_ID {
        if let Some(object) = payload.as_object_mut() {
            object
                .entry("home_id")
                .or_insert_with(|| Value::String(UNFILED_RECORD_ID.into()));
        }
    }
    payload
}

/// Transaction poison rule shared by lifecycle owners.
pub fn interruption_poisoned(error: &SqlError) -> bool {
    matches!(
        error.category,
        ErrorCategory::Cancelled | ErrorCategory::DeadlineExceeded | ErrorCategory::OutcomeUnknown
    )
}

/// Commit cancellation is never reported as an ordinary cancellation: the
/// caller cannot know whether durability happened.
pub fn commit_interruption(control_error: ErrorCategory) -> SqlError {
    debug_assert!(matches!(
        control_error,
        ErrorCategory::Cancelled | ErrorCategory::DeadlineExceeded
    ));
    SqlError::control_for_domain(ErrorCategory::OutcomeUnknown, ExecutionPhase::Commit)
}

fn object_payload(event: &EventRow, payload: Value) -> Result<Map<String, Value>> {
    payload.as_object().cloned().ok_or_else(|| {
        Error::engine(format!(
            "event {} ({}) payload is not an object: {payload}",
            event.id, event.event_type
        ))
    })
}

fn required_kind<'a>(event: &EventRow, value: Option<&'a Value>) -> Result<&'a str> {
    match value {
        Some(Value::String(kind)) if !kind.is_empty() => Ok(kind),
        Some(Value::String(_)) => Err(Error::engine(format!(
            "cannot apply {}: record {} requires a non-empty kind; the empty string is invalid",
            event.event_type, event.record_id
        ))),
        Some(Value::Null) => Err(Error::engine(format!(
            "cannot apply {}: record {} requires a non-null kind",
            event.event_type, event.record_id
        ))),
        Some(other) => Err(Error::engine(format!(
            "cannot apply {}: record {} kind must be a non-empty string, got {other}",
            event.event_type, event.record_id
        ))),
        None => Err(Error::engine(format!(
            "cannot apply {}: record {} requires a kind",
            event.event_type, event.record_id
        ))),
    }
}

fn validate_link_envelope(
    event: &EventRow,
    source_id: &str,
    _target_id: &str,
    _relationship: &str,
) -> Result<()> {
    if source_id != event.record_id {
        return Err(Error::engine(format!(
            "{} envelope mismatch: event.record_id {} !== payload.source_id {}",
            event.event_type, event.record_id, source_id
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn event(event_type: &str, payload: Value) -> EventRow {
        EventRow {
            local_seq: 1,
            id: "event".into(),
            record_id: "record".into(),
            event_type: event_type.into(),
            payload: Some(payload.to_string()),
            actor: None,
            run_key: None,
            parent_key: None,
            intent: None,
            created_at: "2026-08-06T00:00:00.000Z".into(),
            causal_envelope: crate::events::CausalEnvelopeV1::complete(
                crate::events::CausalFrontierV1::empty(),
            ),
        }
    }

    fn semantic_state(record_type: &str) -> RecordSemanticState {
        RecordSemanticState {
            record_type: record_type.into(),
            kind: Some("item".into()),
            persistence: "enduring".into(),
            deleted: false,
            policy_anchor_id: Some(ROOT_RECORD_ID.into()),
            archived: false,
            targeted: false,
            attributed: false,
            semantic_unit: false,
            message_status: None,
        }
    }

    fn correction_payload(from_type: &str, from_kind: &str) -> Value {
        json!({
            "from": {"type": from_type, "kind": from_kind},
            "to": {"type": "Resolution", "kind": "decision"},
            "mode": "confirmed",
            "reason": "Correct a registry-proven wrong type.",
            "plan_id": "plan:test-correction",
            "effect_digest": format!("sha256:{}", "a".repeat(64)),
            "schema_state_revision": "schema-state-v1:meta:1:content:2",
            "confirmation_required": true
        })
    }

    #[derive(Default)]
    struct FakeState {
        records: HashMap<String, RecordSemanticState>,
        cycles: bool,
        children: HashMap<String, String>,
    }

    impl ContentSemanticStatePort for FakeState {
        fn record_state<'a>(
            &'a mut self,
            record_id: &'a str,
        ) -> BoxFuture<'a, Result<Option<RecordSemanticState>>> {
            Box::pin(async move { Ok(self.records.get(record_id).cloned()) })
        }

        fn home_would_cycle<'a>(
            &'a mut self,
            _record_id: &'a str,
            _home_id: &'a str,
        ) -> BoxFuture<'a, Result<bool>> {
            Box::pin(async move { Ok(self.cycles) })
        }

        fn first_live_child<'a>(
            &'a mut self,
            record_id: &'a str,
        ) -> BoxFuture<'a, Result<Option<String>>> {
            Box::pin(async move { Ok(self.children.get(record_id).cloned()) })
        }

        fn link_identity<'a>(
            &'a mut self,
            _source_id: &'a str,
            _target_id: &'a str,
            _relationship: &'a str,
        ) -> BoxFuture<'a, Result<Option<String>>> {
            Box::pin(async move { Ok(None) })
        }
    }

    #[tokio::test]
    async fn dedicated_type_correction_requires_an_exact_from_identity() {
        let mut state = FakeState::default();
        let mut record = semantic_state("Document");
        record.kind = Some("decision".into());
        state.records.insert("record".into(), record);

        let correction = event(
            "record.type_corrected.v1",
            correction_payload("Document", "decision"),
        );
        let intent = ProjectorIntent::from_event(&correction).unwrap();
        let plan = plan_projection(&mut state, &correction, &intent)
            .await
            .unwrap();
        assert!(matches!(
            plan,
            ProjectionPlan::RecordTypeCorrected { record_type, kind }
                if record_type == "Resolution" && kind == "decision"
        ));

        let stale = event(
            "record.type_corrected.v1",
            correction_payload("Entity", "decision"),
        );
        let error = plan_projection(
            &mut state,
            &stale,
            &ProjectorIntent::from_event(&stale).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("no longer matches from identity"));
    }

    #[tokio::test]
    async fn dedicated_type_correction_rejects_specialised_and_malformed_events() {
        let mut state = FakeState::default();
        let mut targeted = semantic_state("Annotation");
        targeted.kind = Some("citation".into());
        targeted.targeted = true;
        state.records.insert("record".into(), targeted);
        let correction = event(
            "record.type_corrected.v1",
            correction_payload("Annotation", "citation"),
        );
        let error = plan_projection(
            &mut state,
            &correction,
            &ProjectorIntent::from_event(&correction).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("targeted Annotation"));

        let mut malformed = correction_payload("Document", "decision");
        malformed["unexpected"] = json!(true);
        assert!(
            ProjectorIntent::from_event(&event("record.type_corrected.v1", malformed)).is_err()
        );

        let mut ordinary = semantic_state("Document");
        ordinary.kind = Some("note".into());
        state.records.insert("record".into(), ordinary);
        let mut target_message = correction_payload("Document", "note");
        target_message["to"] = json!({"type":"Message","kind":"agent"});
        let target_message = event("record.type_corrected.v1", target_message);
        let error = plan_projection(
            &mut state,
            &target_message,
            &ProjectorIntent::from_event(&target_message).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("created atomically"));
    }

    #[test]
    fn record_id_authority_accepts_only_canonical_v4_and_v7_uuids() {
        for record_id in [
            "4d0a20cc-48c3-4f20-a62b-799dc8ef8584",
            "01920b7a-6f2b-7c3d-8e4f-5a6b7c8d9e0f",
        ] {
            assert_eq!(
                record_id_for_create(Some(record_id.into())).unwrap(),
                record_id
            );
        }
        // Shapes that were admitted before this rule, including the exact
        // 128-byte boundary. They are now rejected on write; historical logs
        // carrying them still replay.
        for record_id in [
            "old-home",
            "with.dot_and:colon-dash",
            "release-path-changes-merge-blind",
            "corpus:create:full",
            &"a".repeat(RECORD_ID_MAX_BYTES),
        ] {
            assert_eq!(
                record_id_for_create(Some(record_id.into()))
                    .unwrap_err()
                    .to_string(),
                RECORD_ID_UUID_ERROR,
                "{record_id:?}"
            );
        }
    }

    #[test]
    fn record_id_authority_rejects_deterministic_and_non_canonical_uuids() {
        for record_id in [
            // v1: time/node derived.
            "d9428888-122b-11e1-b85c-61cd3cbb3210",
            // v3: MD5 of namespace + name.
            "3d813cbb-47fb-32ba-91df-831e1593ac29",
            // v5: SHA-1 of namespace + name. Excluded ON PURPOSE and must stay
            // excluded — two databases deriving a v5 from the same business
            // key mint the IDENTICAL id, which is exactly the cross-database
            // collision this rule exists to prevent. Do not "fix" this by
            // widening the accepted set.
            "886313e1-3b8a-5372-9b90-0c9aee199e5d",
            // Nil and max: no version nibble at all.
            "00000000-0000-0000-0000-000000000000",
        ] {
            assert_eq!(
                record_id_for_create(Some(record_id.into()))
                    .unwrap_err()
                    .to_string(),
                RECORD_ID_UUID_ERROR,
                "{record_id:?}"
            );
        }
        // Non-canonical spellings of an otherwise valid v4, rejected by
        // round-trip rather than by a second rule.
        for record_id in [
            "4D0A20CC-48C3-4F20-A62B-799DC8EF8584",
            "4d0a20cc48c34f20a62b799dc8ef8584",
        ] {
            assert_eq!(
                record_id_for_create(Some(record_id.into()))
                    .unwrap_err()
                    .to_string(),
                RECORD_ID_UUID_ERROR,
                "{record_id:?}"
            );
        }
    }

    #[test]
    fn record_id_authority_rejects_malformed_and_reserved_ids_stably() {
        for record_id in [
            "",
            " ",
            "two words",
            " leading",
            "trailing ",
            "line\nbreak",
            "nul\0byte",
            "record/slash",
            "café",
        ] {
            assert_eq!(
                record_id_for_create(Some(record_id.into()))
                    .unwrap_err()
                    .to_string(),
                RECORD_ID_SHAPE_ERROR,
                "{record_id:?}"
            );
        }
        assert_eq!(
            record_id_for_create(Some("a".repeat(RECORD_ID_MAX_BYTES + 1)))
                .unwrap_err()
                .to_string(),
            RECORD_ID_SHAPE_ERROR
        );
        for record_id in [
            "native:",
            "native:anything",
            ROOT_RECORD_ID,
            UNFILED_RECORD_ID,
        ] {
            assert_eq!(
                record_id_for_create(Some(record_id.into()))
                    .unwrap_err()
                    .to_string(),
                RECORD_ID_RESERVED_ERROR
            );
        }
    }

    #[test]
    fn generated_record_ids_are_canonical_lowercase_uuid_v4() {
        let record_id = record_id_for_create(None).unwrap();
        let parsed = Uuid::parse_str(&record_id).unwrap();
        assert_eq!(parsed.get_version(), Some(uuid::Version::Random));
        assert_eq!(parsed.hyphenated().to_string(), record_id);
    }

    #[test]
    fn engine_seed_authority_admits_only_the_canonical_filing_ids() {
        for record_id in [ROOT_RECORD_ID, UNFILED_RECORD_ID] {
            validate_record_id(record_id, RecordIdAuthority::EngineSeed).unwrap();
        }
        for record_id in ["native:anything", "ordinary"] {
            assert!(validate_record_id(record_id, RecordIdAuthority::EngineSeed).is_err());
        }
    }

    #[test]
    fn engine_provisioning_authority_has_an_exact_reserved_allowlist() {
        for record_id in ENGINE_PROVISIONED_RECORD_IDS {
            validate_record_id(record_id, RecordIdAuthority::EngineProvisioning).unwrap();
        }
        validate_record_id(
            "4d0a20cc-48c3-4f20-a62b-799dc8ef8584",
            RecordIdAuthority::EngineProvisioning,
        )
        .unwrap();
        for record_id in [
            ROOT_RECORD_ID,
            UNFILED_RECORD_ID,
            "native:kernel-squat",
            // The non-reserved branch now carries the same UUID requirement.
            "provisioning-slug",
        ] {
            assert!(validate_record_id(record_id, RecordIdAuthority::EngineProvisioning).is_err());
        }
    }

    #[test]
    fn engine_derived_authority_admits_only_the_change_summary_carrier_digest() {
        let digest = "a".repeat(64);
        let carrier = format!("{CHANGE_SUMMARY_CARRIER_PREFIX}{digest}");
        validate_record_id(&carrier, RecordIdAuthority::EngineDerived).unwrap();
        validate_record_id(
            &format!(
                "{CHANGE_SUMMARY_CARRIER_PREFIX}{}",
                "0123456789abcdef".repeat(4)
            ),
            RecordIdAuthority::EngineDerived,
        )
        .unwrap();
        // A UUID still crosses this authority; the exemption only adds one shape.
        validate_record_id(
            "4d0a20cc-48c3-4f20-a62b-799dc8ef8584",
            RecordIdAuthority::EngineDerived,
        )
        .unwrap();
        for record_id in [
            // Sibling namespaces are NOT exempt.
            format!("change-summary:series:{digest}"),
            format!("change-summary:binding:{digest}"),
            format!("change-summary:role:{digest}"),
            // Wrong prefix, including a prefix that merely contains it.
            format!("other:carrier:{digest}"),
            format!("x-change-summary:carrier:{digest}"),
            format!("change-summary:carrier{digest}"),
            // Wrong digest length.
            format!("{CHANGE_SUMMARY_CARRIER_PREFIX}{}", "a".repeat(63)),
            format!("{CHANGE_SUMMARY_CARRIER_PREFIX}{}", "a".repeat(65)),
            CHANGE_SUMMARY_CARRIER_PREFIX.to_string(),
            // Non-lowercase-hex digest.
            format!("{CHANGE_SUMMARY_CARRIER_PREFIX}{}", "A".repeat(64)),
            format!("{CHANGE_SUMMARY_CARRIER_PREFIX}{}", "g".repeat(64)),
            format!("{CHANGE_SUMMARY_CARRIER_PREFIX}{}suffix", "a".repeat(64)),
        ] {
            assert!(
                validate_record_id(&record_id, RecordIdAuthority::EngineDerived).is_err(),
                "{record_id:?}"
            );
        }
        // The carve-out is unreachable from every other authority.
        for authority in [
            RecordIdAuthority::CallerSupplied,
            RecordIdAuthority::Generated,
            RecordIdAuthority::EngineSeed,
            RecordIdAuthority::EngineProvisioning,
        ] {
            assert!(validate_record_id(&carrier, authority).is_err());
        }
        assert_eq!(
            record_id_for_create(Some(carrier.clone()))
                .unwrap_err()
                .to_string(),
            RECORD_ID_UUID_ERROR
        );
    }

    #[tokio::test]
    async fn ordinary_record_update_rejects_mutable_type_after_state_read() {
        let mut state = FakeState::default();
        state
            .records
            .insert("record".into(), semantic_state("Outcome"));
        let event = event("record.updated", json!({"type": "Document"}));
        let intent = ProjectorIntent::from_event(&event).unwrap();
        let error = plan_projection(&mut state, &event, &intent)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("`type` is immutable"));
    }

    #[tokio::test]
    async fn semantic_unit_type_precedes_global_type_rigidity() {
        let mut state = FakeState::default();
        let mut unit = semantic_state("Document");
        unit.semantic_unit = true;
        state.records.insert("record".into(), unit);
        let event = event("record.updated", json!({"type": "Outcome"}));
        let intent = ProjectorIntent::from_event(&event).unwrap();
        let error = plan_projection(&mut state, &event, &intent)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot change Unit record identity envelope through record.updated"
        );
    }

    #[tokio::test]
    async fn semantic_unit_invalid_kind_precedes_global_kind_validation() {
        let mut state = FakeState::default();
        let mut unit = semantic_state("Document");
        unit.semantic_unit = true;
        state.records.insert("record".into(), unit);
        let event = event("record.updated", json!({"kind": ""}));
        let intent = ProjectorIntent::from_event(&event).unwrap();
        let error = plan_projection(&mut state, &event, &intent)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot change Unit record identity envelope through record.updated"
        );
    }

    #[tokio::test]
    async fn finalized_message_fields_precede_global_type_rigidity() {
        let mut state = FakeState::default();
        let mut message = semantic_state("Message");
        message.message_status = Some("sealed".into());
        state.records.insert("record".into(), message);
        let event = event(
            "record.updated",
            json!({"type": "Document", "name": "changed"}),
        );
        let intent = ProjectorIntent::from_event(&event).unwrap();
        let error = plan_projection(&mut state, &event, &intent)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Message fields name are immutable creation content; create a superseding Message"
        );
    }

    #[tokio::test]
    async fn ordinary_record_update_rejects_invalid_kind_after_state_rules() {
        let mut state = FakeState::default();
        state
            .records
            .insert("record".into(), semantic_state("Document"));
        let event = event("record.updated", json!({"kind": ""}));
        let intent = ProjectorIntent::from_event(&event).unwrap();
        let error = plan_projection(&mut state, &event, &intent)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "cannot apply record.updated: record record requires a non-empty kind; the empty string is invalid"
        );
    }

    #[test]
    fn canonical_intent_rejects_link_envelope_before_state_reads() {
        let error = ProjectorIntent::from_event(&event(
            "link.added",
            json!({
                "source_id":"different",
                "target_id":"target",
                "relationship":"references"
            }),
        ))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "link.added envelope mismatch: event.record_id record !== payload.source_id different"
        );
    }

    #[tokio::test]
    async fn shared_home_validation_rejects_archived_and_cyclic_homes() {
        let mut home = semantic_state("Collection");
        home.kind = Some("folder".into());
        home.archived = true;
        let mut state = FakeState::default();
        state.records.insert("home".into(), home.clone());
        let created = event(
            "record.created",
            json!({"type":"Document","kind":"note","home_id":"home"}),
        );
        let intent = ProjectorIntent::from_event(&created).unwrap();
        let error = plan_projection(&mut state, &created, &intent)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("live, unarchived, enduring"));

        home.archived = false;
        state.records.insert("home".into(), home);
        state.cycles = true;
        let error = plan_projection(&mut state, &created, &intent)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("would create a cycle"));
    }

    #[tokio::test]
    async fn shared_folder_rules_reject_archive_delete_and_demotion_with_children() {
        let mut state = FakeState::default();
        let mut folder = semantic_state("Collection");
        folder.kind = Some("folder".into());
        state.records.insert("record".into(), folder);
        state.children.insert("record".into(), "child".into());

        for (event_type, payload) in [
            ("record.deleted", json!({})),
            ("record.updated", json!({"persistence":"occurrent"})),
            ("facet.set", json!({"key":"archived","value":"true"})),
        ] {
            let event = event(event_type, payload);
            let intent = ProjectorIntent::from_event(&event).unwrap();
            let error = plan_projection(&mut state, &event, &intent)
                .await
                .unwrap_err();
            assert!(error.to_string().contains("still has live homed members"));
        }
    }

    #[tokio::test]
    async fn shared_message_link_rules_require_open_content_and_typed_conversation() {
        let mut state = FakeState::default();
        let mut message = semantic_state("Message");
        message.message_status = Some("sealed".into());
        state.records.insert("record".into(), message.clone());
        state
            .records
            .insert("target".into(), semantic_state("Document"));

        let reply = event(
            "link.added",
            json!({"source_id":"record","target_id":"target","relationship":"reply_to"}),
        );
        let error = plan_projection(
            &mut state,
            &reply,
            &ProjectorIntent::from_event(&reply).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("immutable Message content"));

        message.message_status = Some("pending_local".into());
        state.records.insert("record".into(), message);
        let participates = event(
            "link.added",
            json!({"source_id":"record","target_id":"target","relationship":"participates_in"}),
        );
        let error = plan_projection(
            &mut state,
            &participates,
            &ProjectorIntent::from_event(&participates).unwrap(),
        )
        .await
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("Message source and Conversation target"));
    }

    #[tokio::test]
    async fn shared_facet_rules_reject_reserved_and_observation_only_spine_forms() {
        let mut state = FakeState::default();
        state
            .records
            .insert("record".into(), semantic_state("Document"));
        for payload in [
            json!({"key":"archived","value":"false"}),
            json!({"key":"owner","value":"person","observation_only":true}),
        ] {
            let event = event("facet.set", payload);
            let error = plan_projection(
                &mut state,
                &event,
                &ProjectorIntent::from_event(&event).unwrap(),
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(
                if event.payload.as_deref().unwrap().contains("archived") {
                    "only takes the value 'true'"
                } else {
                    "observation-only facet.set for spine facet"
                }
            ));
        }
    }

    #[tokio::test]
    async fn shared_update_plan_emits_only_closed_field_operations() {
        let mut state = FakeState::default();
        state
            .records
            .insert("record".into(), semantic_state("Document"));
        let event = event(
            "record.updated",
            json!({"name":"New", "summary":"Summary", "ignored":"value"}),
        );
        let plan = plan_projection(
            &mut state,
            &event,
            &ProjectorIntent::from_event(&event).unwrap(),
        )
        .await
        .unwrap();
        let ProjectionPlan::RecordUpdated { fields, .. } = plan else {
            panic!("expected record update plan");
        };
        assert_eq!(fields.len(), 2);
        assert!(fields
            .iter()
            .any(|field| matches!(field, RecordFieldUpdate::Name(_))));
        assert!(fields
            .iter()
            .any(|field| matches!(field, RecordFieldUpdate::Summary(_))));
    }

    #[test]
    fn placement_normalization_is_backend_neutral() {
        assert_eq!(
            normalize_event_payload("record", "record.created", json!({"type":"Document"}))
                ["home_id"],
            UNFILED_RECORD_ID
        );
        assert!(
            normalize_event_payload(ROOT_RECORD_ID, "record.created", json!({}))
                .get("home_id")
                .is_none()
        );
    }

    #[test]
    fn member_history_redaction_hides_other_identities_and_recipients() {
        let mut payload = json!({
            "owner_id":"person:sender",
            "nested":{"account_id":"acct:sender","body":"visible"},
            "accounts":["acct:reader","acct:other"]
        });
        redact_history_payload_for_member(&mut payload, "acct:reader");
        assert_eq!(payload["owner_id"], Value::Null);
        assert_eq!(payload["nested"]["account_id"], Value::Null);
        assert_eq!(payload["nested"]["body"], "visible");
        assert_eq!(payload["accounts"], json!(["acct:reader"]));
    }
}

// Keep this backend-only module after the default-surface tests so adding a
// portable adapter seam does not renumber the checked-in default test inventory.
#[cfg(any(feature = "postgres", feature = "turso-local"))]
#[path = "domain_transaction/lifecycle.rs"]
mod lifecycle;
#[cfg(any(feature = "postgres", feature = "turso-local"))]
pub(crate) use lifecycle::{delete_record, RecordLifecyclePhysicalPort};
