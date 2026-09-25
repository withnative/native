//! The host side of an artifact interaction: one MCP tool that takes an
//! untrusted invocation and either commits one declared governed effect or
//! refuses.
//!
//! The supported runtimes are `native.mdx.v2` and `native.html.v1`. This sits outside the
//! `ArtifactRuntime` trait deliberately — v2 needs database access for release
//! and binding resolution, so it is a bespoke async host path rather than a
//! synchronous adapter.
//!
//! Validation order, all server-side, in this order and no other:
//!
//! 1. `source_digest` matches the currently rendered body.
//! 2. `entry_id` names an entry in THAT manifest.
//! 3. every declared slot is filled, and every record slot resolves INSIDE the
//!    bound input — which must be bound, root-exposed and granted exactly as
//!    rendering requires, because an artifact that cannot render must not be
//!    able to write.
//! 4. every supplied value lies within its declared domain.
//! 5. schema, vocabulary and required-facet validation on the resulting write.
//! 6. permission, from the authenticated principal, inside the write
//!    transaction — never from the envelope.
//! 7. for facet writes, compare-and-set against the versions the artifact
//!    observed and must supply for the pair it is writing.
//! 8. commit, attributed to the actor and to the originating artifact.
//!
//! 5b. Optional exact personal-install guard (`alpha_install_guard`, alpha
//! tab L2): when present, checked FIRST inside the write transaction against
//! the same account's install (installed, verified `shell_adopt.v1`,
//! generation CAS, exact artifact/source/version/digest/declaration, View,
//! digest recomputation, plus consented `effects` must include
//! `task.triage-set.v1`), reusing the `alpha_tabs` gate helpers. Scope is
//! narrowed to the declared triage `facet.set`/`facet.unset` pair on
//! `native.html.v1`, checked against the actual parsed entry both before the
//! transaction (clarity) and inside it (boundary). A declared v2 manifest
//! interaction alone, or a matching bundle digest alone, is never effect
//! consent, and consent to triage-set never authorizes another facet or
//! `record.create`. A refusal names the personal install only and never
//! globally disables the artifact. Absent, the path is unchanged.
//! Record-create with a guard is refused
//! (`alpha_guard_unsupported_effect`): the governed-create transaction needs
//! a wider refactor to re-check on its snapshot.
//!
//! A cheap preflight of the caller's Edit capability runs BEFORE step 3's
//! Collection walk, so a caller who could never write cannot make the host
//! enumerate a folder on its behalf. It does not replace step 6: the
//! authoritative decision still happens inside the write transaction, on the
//! same snapshot as the append.
//!
//! One exit is deliberately NOT an `ArtifactIntentResult`: an artifact the
//! caller may not even see is refused with the ordinary missing-record error
//! every tool gives, before this module says anything about it — including
//! whether its digest is stale. Every other exit, refusal or not, is a result.
//!
//! A failure at step 3 or 4 is a rejection, never a confirmation prompt: the
//! artifact asked for something outside what it declared, and no human
//! confirmation could make that admissible. `NeedsConfirmation` is reserved for
//! future irreversible effects and is never produced here.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::{Row, Sqlite, Transaction};

use crate::authorization::Capability;
use crate::db::Db;
use crate::domain_transaction::{facet_set_spec, FacetWrite};
use crate::error::{Error, Result};
use crate::query::{cascade, lens};
use crate::schema::spine_facet_column;
use crate::store::{append_in, AppendSpec};

use native_artifact_runtime::artifact_intents::{
    ArtifactIntentResult, ArtifactInvocation, CompetingActor, FacetVersion, IntentChange,
    IntentError, RESULT_REFRESH_JSON_LIMIT,
};
use native_artifact_runtime::mdx_v2::{
    self, InteractionEffect, RecordCreateDestination, RecordCreateValue, RecordCreateValueDomain,
    RecordCreateValueSource, SlotDomain,
};

use super::super::registry::{Caller, ToolRegistry};
use super::super::ToolKind;
use super::artifacts::{
    resolve_artifact, resolve_bound_input_ports, resolve_bound_input_records, try_render_live_html,
    try_render_live_mdx_v2, BoundPort, V2SnapshotMode,
};
use super::lifecycle::{assert_required_not_worsened, parse_facet_entry, required_violations_in};
use super::{can_record, can_record_in, parse_args, require_record};

const TOOL: &str = "invoke_artifact_interaction";

/// The write an entry resolved to. It carries no facet key and no effect: both
/// stay on the manifest entry, so the two cannot drift apart between the
/// domain check and the append.
struct DeclaredWrite {
    record_id: String,
    /// `Some` for `facet.set`, `None` for `facet.unset`.
    value: Option<Value>,
    /// What the facet held before, for the committed change report.
    before: Option<Value>,
}

fn rejected(invocation: &ArtifactInvocation, code: &str, message: impl Into<String>) -> Value {
    encode(ArtifactIntentResult::rejected(
        correlation(invocation),
        IntentError::new(code, safe_message(message)),
    ))
}

/// Echo the invocation's key back, unless the invocation was so malformed that
/// its key is not a usable identity — a refusal must still be a well-formed
/// result.
fn correlation(invocation: &ArtifactInvocation) -> &str {
    let key = invocation.idempotency_key.as_str();
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        "unattributed"
    } else {
        key
    }
}

/// Bound and flatten a message before it becomes part of an authoritative
/// result. Engine errors are multi-line and unbounded; the result contract is
/// neither.
fn safe_message(message: impl Into<String>) -> String {
    let flattened = message
        .into()
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(500)
        .collect::<String>();
    if flattened.trim().is_empty() {
        "the host refused this invocation".into()
    } else {
        flattened
    }
}

fn encode(result: ArtifactIntentResult) -> Value {
    debug_assert!(
        result.validate_shape().is_ok(),
        "the host must not emit a malformed intent result"
    );
    serde_json::to_value(result).expect("an intent result always serializes")
}

fn invocation_digest(invocation: &ArtifactInvocation) -> Result<String> {
    // `include_next_plan` is deliberately NOT part of this digest: it changes
    // nothing about the committed effect, so a retry with the flag flipped
    // replays the same commit rather than conflicting with it. The plan, if
    // asked for, is attached after the replay resolves, per the current
    // request.
    //
    // `alpha_install_guard`, when present, IS part of the digest: it names a
    // different authorization context, so a guarded creation must never replay
    // as an unguarded one (or across generations). Absent, the digest is
    // byte-identical to the pre-guard shape, preserving existing Workbench
    // idempotency keys.
    let mut envelope = json!({
        "version": invocation.version,
        "artifact_id": invocation.artifact_id,
        "entry_id": invocation.entry_id,
        "source_digest": invocation.source_digest,
        "slots": invocation.slots,
        "values": invocation.values,
        "observed": invocation.observed,
        "gesture": invocation.gesture,
    });
    if let Some(guard) = &invocation.alpha_install_guard {
        envelope["alpha_install_guard"] = json!({
            "package": guard.package,
            "expected_install_event_id": guard.expected_install_event_id,
            "artifact_id": guard.artifact_id,
            "source_revision": guard.source_revision,
            "version": guard.version,
            "digest": guard.digest,
            "declaration_digest": guard.declaration_digest,
        });
    }
    Ok(hex::encode(Sha256::digest(serde_jcs::to_vec(&envelope)?)))
}

/// Whether a facet-write replay candidate carries the same guard authorization
/// context as the invoking call. `stored` is the replayed origin's
/// `alpha_install_guard` field (`None` when the row predates the field);
/// absent — legacy or explicitly unguarded — normalizes to JSON null, so
/// ordinary unguarded replay still matches. Guarded↔unguarded and distinct
/// guard pins never match. Value equality only: observed, values and gesture
/// are deliberately not part of replay identity.
fn facet_guard_context_matches(
    stored: Option<&Value>,
    current: &Option<native_artifact_runtime::artifact_intents::AlphaTabInstallGuard>,
) -> bool {
    let current_value = serde_json::to_value(current).unwrap_or(Value::Null);
    stored.unwrap_or(&Value::Null) == &current_value
}

fn committed_creation(invocation: &ArtifactInvocation, created: Value) -> Value {
    let act = created.get("act").cloned();
    let record_id = created
        .get("id")
        .and_then(Value::as_str)
        .expect("governed create success returns the authoritative record id")
        .to_owned();
    let mut result = encode(ArtifactIntentResult::Committed {
        version: native_artifact_runtime::artifact_intents::INTENT_RESULT_VERSION.into(),
        idempotency_key: invocation.idempotency_key.clone(),
        changes: vec![IntentChange {
            record_id,
            key: "record".into(),
            before: None,
            after: Some(json!({ "created": true })),
            version: None,
        }],
        refresh: Some(json!({ "record": created })),
    });
    // The governed creation this invocation performed allocated exactly one
    // act; hoist it to the top-level write payload alongside the refresh.
    if let Some(act @ Value::Number(_)) = act {
        result["act"] = act;
    }
    result
}

/// Merge a bonus render into a committed `refresh`, shaped like the existing
/// `{ "record": ... }` convention: the fresh `plan` joins under `"plan"` (or
/// beside the created record a creation already refreshed), and the
/// authoritative `input` and `input_digest` the plan was rendered over join
/// as siblings — mirroring the render result's own shape, so the caller can
/// synthesise a settled result and continue with fresh state instead of a
/// second render. `launch` is deliberately not forwarded: a commit never
/// changes the artifact body, so the caller continues in place on its live
/// launch.
///
/// The render fields are forwarded generically: each of `input` and
/// `input_digest` is attached only when the rendered result carries it, so
/// runtimes whose renders omit one still yield a usable bonus.
///
/// Required invariant: all-or-nothing. The merged candidate is size-checked
/// once, so a breach drops plan, input and digest together — the caller must
/// never see a plan without its input. Returns `None` when the rendered
/// result carries no plan, the merged candidate would breach the refresh size
/// cap, or the existing refresh is not an object — the caller then keeps
/// whatever refresh the commit produced, never an invalid result.
fn refresh_with_next_plan(current: Option<&Value>, rendered: &Value) -> Option<Value> {
    let plan = rendered.get("plan")?;
    let mut merged = match current {
        Some(Value::Object(existing)) => existing.clone(),
        Some(_) => return None,
        None => serde_json::Map::new(),
    };
    merged.insert("plan".into(), plan.clone());
    if let Some(input) = rendered.get("input") {
        merged.insert("input".into(), input.clone());
    }
    if let Some(input_digest) = rendered.get("input_digest") {
        merged.insert("input_digest".into(), input_digest.clone());
    }
    let candidate = Value::Object(merged);
    match serde_json::to_vec(&candidate) {
        Ok(bytes) if bytes.len() <= RESULT_REFRESH_JSON_LIMIT => Some(candidate),
        _ => None,
    }
}

/// The next-plan bonus: when the caller opted in with `include_next_plan`
/// and the invocation committed, attach the fresh authoritative plan with the
/// input it was rendered over under `refresh`, collapsing the commit and the
/// re-render into one exchange.
///
/// Only `Committed` results ever carry a plan. A conflict names exactly what
/// moved — `current_version`, the conflicting event, the competing actor —
/// so the caller can decide whether retrying is even right, and a retry
/// starts with a fresh render for new preconditions anyway. Rendering eagerly
/// on the failure path would spend a full render (and an admission permit) at
/// the moment of contention for bytes the caller usually discards: unlike a
/// commit, whose next step is unconditionally "continue with fresh state", a
/// conflict's next step is conditional. Rejections and invalid invocations
/// change nothing durable and ask the caller to fix the request rather than
/// re-read state, so there is nothing new for a plan to reflect there
/// either. So the plan stays a commit-only bonus. Replays are `Committed`,
/// so a replay with the flag set gets a plan too: it describes durable state
/// either way.
///
/// THE WRITE HAS ALREADY SUCCEEDED. The plan is a bonus and must never turn
/// a successful commit into a failure, so nothing here propagates: a render
/// error, a diagnostic without a plan, or a plan that would breach the
/// refresh size cap all degrade to the ordinary committed result. A caller
/// that asked for a plan and did not get one falls back to `render_artifact`
/// — which is exactly today's behaviour, so the fallback is already proven.
async fn maybe_include_next_plan(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    mut result: Value,
) -> Value {
    if !invocation.include_next_plan
        || result.get("status").and_then(Value::as_str) != Some("committed")
    {
        return result;
    }
    // The commit is durable by the time any caller reaches this helper: both
    // `commit_declared_write` (after `db.commit_content`) and
    // `invoke_record_create` (after the governed create returns `Created`)
    // resolve only once the event log holds the write, and the write
    // transaction is closed — there is nothing left to conflict with the
    // render's own reads, so the plan below describes post-write state.
    //
    // Both supported runtimes use their ordinary live materialization path,
    // with one transaction on the live write pool. A missing or diagnostic
    // render degrades to no bonus plan; the committed effect stays successful.
    //
    // Admission is safe by construction: the invoke path holds no mdx permit
    // when this runs — permits are taken only inside render functions via the
    // non-blocking `try_admit`, and the write transaction above is already
    // closed — so the bonus render contends exactly like one concurrent
    // `render_artifact` call. Saturation never waits: it surfaces as a
    // diagnostic, which the status check below turns into no plan.
    let rendered =
        match try_render_live_mdx_v2(db, caller, &invocation.artifact_id, false, None).await {
            Ok(Some(rendered)) => rendered,
            Ok(None) => match try_render_live_html(db, caller, &invocation.artifact_id).await {
                Ok(Some(rendered)) => rendered,
                Ok(None) | Err(_) => return result,
            },
            Err(_) => return result,
        };
    if rendered.get("status").and_then(Value::as_str) != Some("rendered") {
        return result;
    }
    let current = result.get("refresh").filter(|value| !value.is_null());
    if let Some(merged) = refresh_with_next_plan(current, &rendered) {
        result["refresh"] = merged;
    }
    result
}

async fn replayed_creation(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    digest: &str,
) -> Result<Option<Value>> {
    let row = sqlx::query(
        "SELECT record_id,payload,act FROM content_events
          WHERE type='record.created' AND actor=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&invocation.artifact_id)
    .bind(&invocation.entry_id)
    .bind(&invocation.idempotency_key)
    .fetch_optional(db.pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let replayed_act: Option<i64> = row.try_get("act")?;
    let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
    if payload
        .pointer("/origin/invocation_digest")
        .and_then(Value::as_str)
        != Some(digest)
    {
        return Ok(Some(rejected(
            invocation,
            "idempotency_conflict",
            "the idempotency key was already used for a different invocation",
        )));
    }
    let record_id: String = row.try_get("record_id")?;
    let mut created = super::lifecycle::read_artifact_created_record(db, caller, &record_id)
        .await
        .map_err(|_| {
            Error::engine(format!(
                "{TOOL}: committed creation readback is uncertain; retry with the same idempotency_key"
            ))
        })?;
    created
        .as_object_mut()
        .expect("authoritative created record is an object")
        .insert("idempotent_retry".into(), Value::Bool(true));
    // A keyed replay returns the original creation's act; `committed_creation`
    // hoists it to the top level.
    if let Some(act) = replayed_act {
        created
            .as_object_mut()
            .expect("authoritative created record is an object")
            .insert("act".into(), act.into());
    }
    Ok(Some(committed_creation(invocation, created)))
}

/// Name the binding a refusal was measured against, so "outside the bound
/// input" says which input.
fn describe(bound: &[&BoundPort]) -> String {
    if bound.is_empty() {
        return "no bound input".into();
    }
    bound
        .iter()
        .map(|input| format!("{}={}", input.port, input.collection_id))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Turn an artifact diagnostic into an authoritative result.
///
/// One tool, one wire shape: a client deserializing `ArtifactIntentResult` must
/// not meet `{"status":"error"}` from the shared artifact diagnostic helper. The
/// diagnostic's own code is preserved, so nothing is lost in the translation.
fn from_diagnostic(invocation: &ArtifactInvocation, value: &Value) -> Value {
    let diagnostic = value.get("diagnostic").unwrap_or(&Value::Null);
    let code = diagnostic
        .get("code")
        .and_then(Value::as_str)
        .unwrap_or("artifact_unavailable");
    let message = diagnostic
        .get("message")
        .and_then(Value::as_str)
        .unwrap_or("the artifact could not be resolved");
    rejected(invocation, code, message)
}

fn create_value_declarations(
    create: &mdx_v2::RecordCreateDecl,
) -> impl Iterator<Item = &RecordCreateValue> {
    std::iter::once(&create.shape.record_type)
        .chain(std::iter::once(&create.shape.kind))
        .chain(create.shape.fields.values())
        .chain(create.shape.facets.values())
}

fn scalar_domain_admits(domain: &RecordCreateValueDomain, value: &Value) -> bool {
    match domain {
        RecordCreateValueDomain::Enum { values } => values.iter().any(|member| {
            member == value
                || member
                    .as_f64()
                    .zip(value.as_f64())
                    .is_some_and(|(declared, supplied)| {
                        declared.is_finite() && supplied.is_finite() && declared == supplied
                    })
        }),
        RecordCreateValueDomain::String {
            min_length,
            max_length,
        } => value.as_str().is_some_and(|value| {
            let length = value.chars().count();
            (*min_length..=*max_length).contains(&length)
        }),
        RecordCreateValueDomain::Number { min, max, step } => {
            let Some(number) = value.as_f64().filter(|value| value.is_finite()) else {
                return false;
            };
            if min.is_some_and(|bound| number < bound) || max.is_some_and(|bound| number > bound) {
                return false;
            }
            step.is_none_or(|step| {
                let origin = min.unwrap_or(0.0);
                let quotient = (number - origin) / step;
                (quotient - quotient.round()).abs() <= 1e-9 * quotient.abs().max(1.0)
            })
        }
        RecordCreateValueDomain::Boolean => value.is_boolean(),
        RecordCreateValueDomain::Date { min, max } => value.as_str().is_some_and(|value| {
            let Ok(date) = chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d") else {
                return false;
            };
            let lower = min
                .as_deref()
                .and_then(|value| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").ok());
            let upper = max
                .as_deref()
                .and_then(|value| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d").ok());
            lower.is_none_or(|bound| date >= bound) && upper.is_none_or(|bound| date <= bound)
        }),
        RecordCreateValueDomain::Datetime { min, max } => value.as_str().is_some_and(|value| {
            let Ok(datetime) = chrono::DateTime::parse_from_rfc3339(value) else {
                return false;
            };
            let lower = min
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
            let upper = max
                .as_deref()
                .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
            lower.is_none_or(|bound| datetime >= bound)
                && upper.is_none_or(|bound| datetime <= bound)
        }),
        RecordCreateValueDomain::BoundInput { .. } => false,
        RecordCreateValueDomain::List {
            min_items,
            max_items,
            item,
        } => value.as_array().is_some_and(|values| {
            (*min_items..=*max_items).contains(&values.len())
                && values.iter().all(|value| scalar_domain_admits(item, value))
        }),
    }
}

fn resolve_create_value(
    declaration: &RecordCreateValue,
    invocation: &ArtifactInvocation,
    records_by_port: &BTreeMap<String, BTreeSet<String>>,
) -> std::result::Result<Value, (&'static str, String)> {
    let (value, input_name) = match &declaration.source {
        RecordCreateValueSource::Literal { value } => (value.clone(), None),
        RecordCreateValueSource::Input { input } => (
            invocation.values.get(input).cloned().ok_or_else(|| {
                (
                    "slot_unfilled",
                    format!("creation input '{input}' is unfilled"),
                )
            })?,
            Some(input.as_str()),
        ),
        RecordCreateValueSource::BoundInput { slot } => {
            let record_id = invocation.slots.get(slot).cloned().ok_or_else(|| {
                (
                    "slot_unfilled",
                    format!("bound record input '{slot}' is unfilled"),
                )
            })?;
            let RecordCreateValueDomain::BoundInput { port } = &declaration.domain else {
                return Err((
                    "invalid_declaration",
                    format!("bound record input '{slot}' has no bound-input domain"),
                ));
            };
            if !records_by_port
                .get(port)
                .is_some_and(|records| records.contains(&record_id))
            {
                return Err((
                    "record_outside_binding",
                    format!("record {record_id} is outside bound input '{port}'"),
                ));
            }
            return Ok(Value::String(record_id));
        }
    };
    if !scalar_domain_admits(&declaration.domain, &value) {
        return Err((
            "value_outside_domain",
            format!(
                "value for creation input '{}' is outside its declared domain",
                input_name.unwrap_or("literal")
            ),
        ));
    }
    Ok(value)
}

async fn invoke_record_create(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
    invocation_digest: &str,
) -> Result<Value> {
    let Some(create) = entry.create.as_ref() else {
        return Ok(rejected(
            invocation,
            "invalid_declaration",
            "record.create entry has no creation declaration",
        ));
    };
    if create_value_declarations(create)
        .any(|declaration| matches!(&declaration.domain, RecordCreateValueDomain::List { .. }))
    {
        return Ok(rejected(
            invocation,
            "unsupported_domain",
            "bounded list creation is unavailable until the governed record transaction admits multi-value data",
        ));
    }
    if create.shape.facets.values().any(|declaration| {
        matches!(&declaration.domain, RecordCreateValueDomain::Boolean)
            || matches!(&declaration.domain, RecordCreateValueDomain::Enum { values }
                if values.iter().any(Value::is_boolean))
    }) {
        return Ok(rejected(
            invocation,
            "unsupported_domain",
            "boolean facet creation is unavailable until governed facet persistence admits booleans",
        ));
    }
    if !invocation.observed.is_empty() {
        return Ok(rejected(
            invocation,
            "unexpected_precondition",
            "record.create does not accept facet compare-and-set preconditions",
        ));
    }

    let read_lens = lens::ReadLens::live(db);
    let ports = match resolve_bound_input_ports(
        &read_lens,
        caller,
        &invocation.artifact_id,
        manifest,
        source_event_id,
        &invocation.source_digest,
    )
    .await?
    {
        Ok(ports) => ports,
        Err(diagnostic) => return Ok(from_diagnostic(invocation, &diagnostic)),
    };
    let (destination, destination_binding) = match &create.destination {
        RecordCreateDestination::Literal { record_id } => (record_id.clone(), None),
        RecordCreateDestination::BoundInput { port } => {
            let Some(bound) = ports
                .iter()
                .find(|bound| bound.port == *port && bound.writable_records)
            else {
                return Ok(rejected(
                    invocation,
                    "named_input_unbound",
                    format!("destination input port '{port}' is not bound to a Collection"),
                ));
            };
            if !bound.root_readable {
                return Ok(rejected(
                    invocation,
                    "module_capability_denied",
                    format!(
                        "destination input port '{port}' is not exposed with an exact input.read grant"
                    ),
                ));
            }
            (
                bound.collection_id.clone(),
                Some(super::lifecycle::ArtifactCreateBindingGuard {
                    port: port.clone(),
                    collection_id: bound.collection_id.clone(),
                }),
            )
        }
    };
    // Preflight before walking any reference-bearing Collection. The ordinary
    // create transaction repeats this authorization on its write snapshot.
    if !can_record(db, caller, &destination, Capability::Edit).await? {
        return Ok(rejected(
            invocation,
            "permission_denied",
            format!("the authenticated principal may not create in {destination}"),
        ));
    }

    let mut declared_values = BTreeSet::new();
    let mut declared_slots = BTreeSet::new();
    let mut reference_ports = BTreeSet::new();
    for declaration in create_value_declarations(create) {
        match &declaration.source {
            RecordCreateValueSource::Literal { .. } => {}
            RecordCreateValueSource::Input { input } => {
                declared_values.insert(input.as_str());
            }
            RecordCreateValueSource::BoundInput { slot } => {
                declared_slots.insert(slot.as_str());
                if let RecordCreateValueDomain::BoundInput { port } = &declaration.domain {
                    reference_ports.insert(port.as_str());
                }
            }
        }
    }
    if let Some(extra) = invocation
        .values
        .keys()
        .find(|name| !declared_values.contains(name.as_str()))
        .or_else(|| {
            invocation
                .slots
                .keys()
                .find(|name| !declared_slots.contains(name.as_str()))
        })
    {
        return Ok(rejected(
            invocation,
            "unknown_slot",
            format!(
                "record.create entry '{}' declares no input '{extra}'",
                entry.id
            ),
        ));
    }

    let mut records_by_port = BTreeMap::new();
    for port in reference_ports {
        let Some(bound) = ports
            .iter()
            .find(|bound| bound.port == port && bound.writable_records && bound.root_readable)
        else {
            return Ok(rejected(
                invocation,
                "named_input_unbound",
                format!("reference input port '{port}' is unavailable"),
            ));
        };
        match resolve_bound_input_records(&read_lens, caller, &invocation.artifact_id, bound)
            .await?
        {
            Ok(records) => {
                records_by_port.insert(port.to_owned(), records);
            }
            Err(diagnostic) => return Ok(from_diagnostic(invocation, &diagnostic)),
        }
    }

    let resolve = |declaration: &RecordCreateValue| {
        resolve_create_value(declaration, invocation, &records_by_port)
    };
    let record_type = match resolve(&create.shape.record_type) {
        Ok(Value::String(value)) => value,
        Ok(_) => {
            return Ok(rejected(
                invocation,
                "invalid_record_shape",
                "record type must resolve to a string",
            ))
        }
        Err((code, message)) => return Ok(rejected(invocation, code, message)),
    };
    let kind = match resolve(&create.shape.kind) {
        Ok(Value::String(value)) => value,
        Ok(_) => {
            return Ok(rejected(
                invocation,
                "invalid_record_shape",
                "record kind must resolve to a string",
            ))
        }
        Err((code, message)) => return Ok(rejected(invocation, code, message)),
    };
    if record_type == "Message"
        || (record_type == "Annotation"
            && ["attribution", "citation", "comment"].contains(&kind.as_str()))
    {
        return Ok(rejected(
            invocation,
            "specialized_creation_required",
            format!("{record_type}/{kind} is created only by its specialized governed workflow"),
        ));
    }

    let mut arguments = serde_json::Map::from_iter([
        ("type".into(), Value::String(record_type)),
        ("kind".into(), Value::String(kind)),
        ("home_id".into(), Value::String(destination)),
        (
            "reason".into(),
            Value::String(format!(
                "Artifact interaction '{}' ({}) created this record.",
                entry.id, entry.label
            )),
        ),
    ]);
    const CREATE_FIELDS: &[&str] = &[
        "name",
        "body",
        "summary",
        "lifecycle",
        "persistence",
        "maturity",
    ];
    for (key, declaration) in &create.shape.fields {
        if !CREATE_FIELDS.contains(&key.as_str()) {
            return Ok(rejected(
                invocation,
                "unsupported_field",
                format!("record.create cannot initialize field '{key}'"),
            ));
        }
        match resolve(declaration) {
            Ok(value) => {
                arguments.insert(key.clone(), value);
            }
            Err((code, message)) => return Ok(rejected(invocation, code, message)),
        }
    }
    let mut facets = serde_json::Map::new();
    for (key, declaration) in &create.shape.facets {
        match resolve(declaration) {
            Ok(value) => {
                facets.insert(key.clone(), value);
            }
            Err((code, message)) => return Ok(rejected(invocation, code, message)),
        }
    }
    if !facets.is_empty() {
        arguments.insert("facets".into(), Value::Object(facets));
    }
    let arguments = Value::Object(arguments);
    let intent_digest = hex::encode(Sha256::digest(serde_jcs::to_vec(&json!({
        "source_digest": invocation.source_digest,
        "arguments": &arguments,
    }))?));
    let references = create_value_declarations(create)
        .filter(|declaration| {
            matches!(
                &declaration.source,
                RecordCreateValueSource::BoundInput { .. }
            )
        })
        .map(|declaration| {
            let RecordCreateValueSource::BoundInput { slot } = &declaration.source else {
                unreachable!("filtered to bound-input sources")
            };
            let RecordCreateValueDomain::BoundInput { port } = &declaration.domain else {
                unreachable!("validated bound-input sources carry bound-input domains")
            };
            let bound = ports
                .iter()
                .find(|bound| bound.port == *port && bound.writable_records)
                .expect("resolved bound reference retains its exact writable port");
            super::lifecycle::ArtifactCreateReferenceGuard {
                port: port.clone(),
                collection_id: bound.collection_id.clone(),
                collection_kind: bound.kind.clone(),
                record_id: invocation
                    .slots
                    .get(slot)
                    .expect("resolved bound input slot remains filled")
                    .clone(),
            }
        })
        .collect();
    let plan = super::lifecycle::ArtifactCreatePlan {
        artifact_id: invocation.artifact_id.clone(),
        entry_id: entry.id.clone(),
        source_digest: invocation.source_digest.clone(),
        source_event_id: source_event_id.to_owned(),
        idempotency_key: invocation.idempotency_key.clone(),
        intent_digest,
        invocation_digest: invocation_digest.to_owned(),
        gesture: invocation.gesture.clone(),
        destination_binding,
        references,
    };
    let created = match super::lifecycle::create_record_from_artifact(
        db.clone(),
        caller.clone(),
        arguments,
        plan,
    )
    .await
    {
        Ok(super::lifecycle::ArtifactCreateOutcome::Created(created)) => created,
        Ok(super::lifecycle::ArtifactCreateOutcome::Rejected { code, message }) => {
            return Ok(rejected(invocation, code, message))
        }
        Ok(super::lifecycle::ArtifactCreateOutcome::Uncertain) => {
            return Err(Error::engine(format!(
                "{TOOL}: record creation committed but authoritative readback is uncertain; retry with the same idempotency_key"
            )))
        }
        Err(_) => {
            return Err(Error::engine(format!(
                "{TOOL}: record creation outcome is uncertain; retry with the same idempotency_key"
            )))
        }
    };
    Ok(committed_creation(invocation, created))
}

async fn invoke_artifact_interaction(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let invocation: ArtifactInvocation = parse_args(TOOL, arguments)?;
    if let Err(message) = invocation.validate_shape() {
        return Ok(encode(ArtifactIntentResult::invalid(
            correlation(&invocation),
            IntentError::new("invalid_invocation", message),
        )));
    }
    let invocation_digest = invocation_digest(&invocation)?;
    // The artifact must be one this caller may see before anything about it —
    // including whether its digest is stale — is reported back.
    require_record(
        &db,
        &caller,
        TOOL,
        &invocation.artifact_id,
        Capability::View,
    )
    .await?;
    if let Some(replayed) = replayed_creation(&db, &caller, &invocation, &invocation_digest).await?
    {
        return Ok(maybe_include_next_plan(&db, &caller, &invocation, replayed).await);
    }
    let read_lens = lens::ReadLens::live(&db);
    let resolved = match resolve_artifact(
        &read_lens,
        &caller,
        &invocation.artifact_id,
        V2SnapshotMode::InspectOnly,
        false,
    )
    .await?
    {
        Ok(resolved) => resolved,
        Err(diagnostic) => return Ok(from_diagnostic(&invocation, &diagnostic)),
    };
    if !matches!(
        resolved.runtime_id.as_str(),
        mdx_v2::RUNTIME_ID | crate::artifact_html::RUNTIME_ID
    ) {
        return Ok(rejected(
            &invocation,
            "unsupported_runtime",
            format!(
                "interaction entries require native.mdx.v2 or native.html.v1; {} declares none",
                resolved.runtime_id
            ),
        ));
    }
    let source_event_id = resolved
        .body_event_id
        .clone()
        .expect("a resolved artifact carries its source event id");
    let partition = caller.hosting_principal().unwrap_or("local").to_owned();
    let body = resolved.body.clone();
    let (source_sha256, manifest) = if resolved.runtime_id == crate::artifact_html::RUNTIME_ID {
        match crate::artifact_html::validate_cached(&body) {
            Ok(manifest) => (
                manifest.body_digest.clone(),
                manifest.interaction_manifest(),
            ),
            Err(failure) => {
                return Ok(rejected(
                    &invocation,
                    "invalid_artifact_body",
                    failure.message,
                ))
            }
        }
    } else {
        let parsed = match tokio::task::spawn_blocking(move || {
            mdx_v2::parse_artifact_cached(&body, &partition)
        })
        .await
        .map_err(|_| Error::engine(format!("{TOOL}: artifact compiler worker terminated")))?
        {
            Ok((parsed, _cache_state)) => parsed,
            Err(failure) => {
                return Ok(rejected(
                    &invocation,
                    "invalid_artifact_body",
                    failure.message,
                ))
            }
        };
        let mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("an artifact source yields an artifact manifest");
        };
        (parsed.source_sha256, manifest)
    };

    // 1. A stale artifact cannot invoke against an edited manifest.
    if source_sha256 != invocation.source_digest {
        return Ok(rejected(
            &invocation,
            "stale_source_digest",
            "the artifact body has changed since this artifact was rendered; re-render and retry",
        ));
    }
    // 2. The entry must be declared in THAT manifest.
    let Some(entry) = manifest.interaction(&invocation.entry_id) else {
        return Ok(rejected(
            &invocation,
            "unknown_entry",
            format!(
                "artifact declares no interaction entry '{}'",
                invocation.entry_id
            ),
        ));
    };
    if let Some(_guard) = &invocation.alpha_install_guard {
        // Guard scope, pre-transaction, on the actual parsed entry and the
        // resolved runtime — never caller effect text. Consent to
        // task.triage-set.v1 authorizes only the declared triage
        // facet.set/unset pair on native.html.v1. The same checks repeat
        // inside the write transaction (see commit_declared_write), so this
        // early refusal is clarity, not the security boundary.
        if entry.effect == InteractionEffect::RecordCreate {
            // L2 slice is facet-only: a guard on a creation would need the
            // governed-create transaction (`create_record_from_artifact`) to
            // re-check the install on its write snapshot, a wider refactor.
            // Fail closed rather than enforce a preflight-only gate that a
            // disable→create race could slip past.
            return Ok(rejected(
                &invocation,
                "alpha_guard_unsupported_effect",
                "the personal-install guard applies only to the declared triage facet.set/facet.unset pair; record.create with a guard is refused",
            ));
        }
        if resolved.runtime_id != crate::artifact_html::RUNTIME_ID {
            return Ok(rejected(
                &invocation,
                "alpha_guard_unsupported_runtime",
                "the personal-install guard requires native.html.v1, matching the alpha launch path",
            ));
        }
        if !matches!(
            entry.effect,
            InteractionEffect::FacetSet | InteractionEffect::FacetUnset
        ) || entry.facet != super::alpha_tabs::ALPHA_GUARD_FACET
        {
            return Ok(rejected(
                &invocation,
                "alpha_guard_facet_unconsented",
                format!(
                    "the personal-install guard consents only to facet '{}'; entry '{}' targets '{}'",
                    super::alpha_tabs::ALPHA_GUARD_FACET,
                    entry.id,
                    entry.facet,
                ),
            ));
        }
    }
    if entry.effect == InteractionEffect::RecordCreate {
        let created = invoke_record_create(
            &db,
            &caller,
            &invocation,
            entry,
            &manifest,
            &source_event_id,
            &invocation_digest,
        )
        .await?;
        return Ok(maybe_include_next_plan(&db, &caller, &invocation, created).await);
    }
    // 3. Every declared slot filled; the record slot resolved inside the
    //    binding. The host derives scope from the binding — the artifact never
    //    states its own.
    let (record_slot, record_domain) = entry
        .slots
        .iter()
        .find(|(_, declaration)| declaration.domain.is_record())
        .map(|(name, declaration)| (name.clone(), declaration.domain.clone()))
        .expect("a compiled entry declares exactly one bound_input slot");
    let Some(record_id) = invocation.slots.get(&record_slot).cloned() else {
        return Ok(rejected(
            &invocation,
            "slot_unfilled",
            format!("record slot '{record_slot}' is unfilled"),
        ));
    };
    for name in invocation.slots.keys().chain(invocation.values.keys()) {
        if !entry.slots.contains_key(name) {
            return Ok(rejected(
                &invocation,
                "unknown_slot",
                format!("entry '{}' declares no slot '{name}'", entry.id),
            ));
        }
    }
    let only_port = match &record_domain {
        SlotDomain::BoundInput { port } => port.clone(),
        SlotDomain::Values { .. } => unreachable!("the record slot is a bound_input domain"),
    };
    let ports = match resolve_bound_input_ports(
        &read_lens,
        &caller,
        &invocation.artifact_id,
        &manifest,
        &source_event_id,
        &source_sha256,
    )
    .await?
    {
        Ok(ports) => ports,
        Err(diagnostic) => return Ok(from_diagnostic(&invocation, &diagnostic)),
    };
    // An unqualified record slot can reach EVERY bound port, so every bound
    // port must then be root-readable. A slot that names its port is judged on
    // that port alone, which is how an artifact forwarding a private input to a
    // module keeps a usable interaction entry.
    let scope = ports
        .iter()
        .filter(|bound| {
            bound.writable_records && only_port.as_deref().is_none_or(|port| port == bound.port)
        })
        .collect::<Vec<_>>();
    if scope.is_empty() {
        return Ok(rejected(
            &invocation,
            "named_input_unbound",
            match &only_port {
                Some(port) => format!("input port '{port}' is not bound to a Collection"),
                None => "this artifact has no bound input to write into".into(),
            },
        ));
    }
    if let Some(ungranted) = scope.iter().find(|bound| !bound.root_readable) {
        // The caller's authority is not the artifact's. This grant is the human
        // consent that this exact source may touch this input, and revoking it
        // must stop writes the same moment it stops renders.
        return Ok(rejected(
            &invocation,
            "module_capability_denied",
            format!(
                "input port '{}' is not exposed to the artifact root with an exact input.read grant",
                ungranted.port
            ),
        ));
    }
    // Preflight, before any Collection walk: a caller who cannot write must not
    // be able to make the host enumerate one. Step 6 still decides.
    if !can_record(&db, &caller, &record_id, Capability::Edit).await? {
        return Ok(rejected(
            &invocation,
            "permission_denied",
            format!("the authenticated principal may not edit record {record_id}"),
        ));
    }
    let mut in_binding = BTreeSet::new();
    for bound in &scope {
        match resolve_bound_input_records(&read_lens, &caller, &invocation.artifact_id, bound)
            .await?
        {
            Ok(records) => in_binding.extend(records),
            Err(diagnostic) => return Ok(from_diagnostic(&invocation, &diagnostic)),
        }
    }
    if !in_binding.contains(&record_id) {
        return Ok(rejected(
            &invocation,
            "record_outside_binding",
            format!(
                "record {record_id} is not inside this artifact's bound input ({})",
                describe(&scope)
            ),
        ));
    }
    // A precondition may only be asserted over records the artifact can
    // actually see through its binding.
    if let Some(outside) = invocation
        .observed
        .keys()
        .find(|record| !in_binding.contains(*record))
    {
        return Ok(rejected(
            &invocation,
            "record_outside_binding",
            format!(
                "record {outside} is not inside this artifact's bound input ({})",
                describe(&scope)
            ),
        ));
    }
    // 4. Every supplied value lies within its declared domain. A literal is a
    //    domain of size one, so it runs through the same check at width one.
    let value = match entry.effect {
        InteractionEffect::RecordCreate => {
            unreachable!("record.create dispatches before the facet write path")
        }
        InteractionEffect::FacetUnset => None,
        InteractionEffect::FacetSet => {
            let source = entry
                .value
                .as_ref()
                .expect("a compiled facet.set entry declares a value");
            let domain = source
                .domain(entry)
                .expect("a compiled value source names a declared slot");
            let supplied = source
                .slot_name()
                .and_then(|slot| invocation.values.get(slot));
            match (supplied, domain.sole_member()) {
                (Some(value), _) if domain.admits(value) => Some(value.clone()),
                (Some(value), _) => {
                    return Ok(rejected(
                        &invocation,
                        "value_outside_domain",
                        format!(
                            "value {value} is outside the domain entry '{}' declares",
                            entry.id
                        ),
                    ))
                }
                (None, Some(sole)) => Some(sole.clone()),
                (None, None) => {
                    return Ok(rejected(
                        &invocation,
                        "slot_unfilled",
                        format!(
                            "entry '{}' needs a value from its declared domain",
                            entry.id
                        ),
                    ))
                }
            }
        }
    };
    // The pair this invocation is about to move must carry a precondition.
    // Without one the default would be silent last-write-wins, which the
    // facet-scoped compare-and-set decision refused.
    if !invocation
        .observed
        .get(&record_id)
        .is_some_and(|facets| facets.contains_key(&entry.facet))
    {
        return Ok(rejected(
            &invocation,
            "precondition_required",
            format!(
                "invocation must observe facet '{}' on record {record_id}; read it back and retry",
                entry.facet
            ),
        ));
    }
    let write = DeclaredWrite {
        record_id,
        value,
        before: None,
    };
    let committed = commit_declared_write(&db, &caller, entry, write, &invocation).await?;
    let mut encoded = encode(committed.0);
    if let Some(act) = committed.1 {
        encoded["act"] = act.into();
    }
    Ok(maybe_include_next_plan(&db, &caller, &invocation, encoded).await)
}

/// The one function in this module that appends, and it cannot be called
/// without a compiled manifest entry.
///
/// The signature carries the requirement: it takes an
/// [`mdx_v2::InteractionEntry`] by reference rather than a facet key, an effect
/// or a value, so a caller must first have FOUND a declared entry in the
/// manifest compiled from the exact body the invocation cited.
/// `the_write_path_is_reachable_only_through_a_manifest_entry` is a tripwire
/// over this file, not a proof: it reads its own source and matches literals,
/// so a second module, an aliased import or a line-broken call would slip past
/// it. It catches the drift that actually happens — someone adding a second
/// append here — and nothing more.
///
/// Steps 5–8 all happen under one `BEGIN IMMEDIATE` transaction: the reserved
/// write lock is what makes read-then-guard-then-append genuinely serialized,
/// so a compare-and-set here cannot be raced. The guard deliberately does NOT
/// live in `plan_facet_set` — `plan_projection` runs for every event during
/// replay and rebuild, so a precondition there would fail every rebuild, for
/// the same reason the `vocab_ref` check is documented as staying out of it.
async fn commit_declared_write(
    db: &Db,
    caller: &Caller,
    entry: &mdx_v2::InteractionEntry,
    mut write: DeclaredWrite,
    invocation: &ArtifactInvocation,
) -> Result<(ArtifactIntentResult, Option<i64>)> {
    let refuse = |code: &str, message: String| {
        Ok((
            ArtifactIntentResult::rejected(
                &invocation.idempotency_key,
                IntentError::new(code, safe_message(message)),
            ),
            None,
        ))
    };
    let key = entry.facet.clone();
    let spine = spine_facet_column(&key);
    // Defence in depth. `validate_interactions` refuses a dispatched key at
    // compile time, so an artifact declaring one never attests; this is the
    // second lock, because the engine hard-dispatches on these keys through
    // tools that do more than the Edit checked here — a byte-identical
    // `archived` event from this path would archive a record for any Edit
    // holder, and a `runtime` written here would skip the prospective-body
    // validators that run wherever it is legitimately set.
    if mdx_v2::ENGINE_DISPATCHED_FACET_KEYS.contains(&key.as_str()) {
        return refuse(
            "unsupported_facet",
            format!(
                "facet '{key}' is engine-dispatched and is written only by the tool that owns it"
            ),
        );
    }
    if spine == Some("owner_id") {
        return refuse(
            "unsupported_facet",
            "owner is a governed identity binding, not an artifact-writable facet".into(),
        );
    }
    if spine.is_some() && write.value.is_none() {
        return refuse(
            "unsupported_facet",
            format!("spine facet '{key}' cannot be cleared through an artifact interaction"),
        );
    }
    if spine.is_some() && write.value.as_ref().is_some_and(|value| !value.is_string()) {
        return refuse(
            "unsupported_facet",
            format!("spine facet '{key}' takes a string value"),
        );
    }
    // Every outgoing value is built as a `FacetWrite` so that ONE governance
    // call judges it, whichever event carries it.
    //
    // Open facets go through the same parser every other facet-writing tool
    // uses: it owns the dispatched-key and spine-key refusals and the
    // admissible value types, so a declared boolean is refused here rather than
    // reaching `FacetWrite::stored_value`, whose `unreachable!` assumes this
    // call happened. A spine key cannot go through that parser — it refuses
    // spine keys by design — but it carries the same declared `values` set and
    // the same governing vocabulary as any other key, and `update_record`
    // validates it through this helper too. So it is built directly here and
    // judged identically. The append branch below still routes it to
    // `record.updated`: a spine write never reaches `facet_set_spec`.
    let mut governed: Vec<FacetWrite> = match (spine, write.value.clone()) {
        (Some(_), Some(value)) => vec![FacetWrite {
            key: key.clone(),
            value,
            vocab_ref: None,
        }],
        (Some(_), None) => unreachable!("spine clears are refused above"),
        (None, _) => {
            let supplied = write.value.clone().unwrap_or(Value::Null);
            match parse_facet_entry(TOOL, &key, &supplied, write.value.is_none()) {
                Ok(facet) => facet.into_iter().collect(),
                Err(error) => return refuse("unsupported_facet", error.to_string()),
            }
        }
    };

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();

    // 5b. Optional exact personal-install guard (alpha tab, task 26ba75a L2).
    // Checked FIRST inside the write transaction — before permission, replay,
    // schema and CAS — on the same snapshot as the append, so a concurrent
    // disable/remove/reinstall (which also takes BEGIN IMMEDIATE) serializes
    // with this write. Scope (triage facet.set/unset on native.html.v1) is
    // re-checked here against the actual parsed `entry`, matching the
    // pre-transaction refusal above; the pre-tx check is clarity, this is the
    // boundary. A refusal names the personal install only; it never claims
    // the artifact is globally disabled for other Workbench use. Absent,
    // this step is skipped and existing callers are unchanged.
    if let Some(guard) = &invocation.alpha_install_guard {
        if let Some((code, message)) = super::alpha_tabs::check_alpha_install_guard_in(
            &mut tx,
            caller,
            guard,
            &invocation.artifact_id,
            &invocation.source_digest,
            entry,
        )
        .await?
        {
            return refuse(&code, message);
        }
    }

    // 6. Permission, server-side, from the AUTHENTICATED PRINCIPAL, inside the
    //    same transaction and snapshot as the append. Nothing in the envelope
    //    contributes to this decision, and the earlier preflight does not
    //    substitute for it.
    if !can_record_in(&mut tx, caller, &write.record_id, Capability::Edit).await? {
        return refuse(
            "permission_denied",
            format!(
                "the authenticated principal may not edit record {}",
                write.record_id
            ),
        );
    }
    let Some(current) =
        sqlx::query("SELECT type, kind FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&write.record_id)
            .fetch_optional(&mut *tx)
            .await?
    else {
        return refuse(
            "missing_record",
            format!("record {} does not exist", write.record_id),
        );
    };
    let record_type: String = current.try_get("type")?;
    let record_kind: Option<String> = current.try_get("kind")?;

    // A replayed invocation commits once. The key rides in the event payload,
    // so the answer comes from the log itself rather than a side table that
    // could disagree with it — but the match is scoped to the same actor,
    // artifact and entry, because the key is client-chosen and one caller must
    // not be able to pre-burn another's. The persisted guard authorization
    // context is compared below: a guarded write must never replay as an
    // unguarded one (or across guard generations), mirroring the creation
    // path's `invocation_digest` conflict. Observed, values and gesture stay
    // out of the comparison — ordinary unguarded replay semantics are
    // unchanged.
    let replayed_row: Option<(i64, String)> = sqlx::query_as(
        "SELECT seq, payload FROM content_events
          WHERE record_id=? AND actor=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(&write.record_id)
    .bind(caller.actor())
    .bind(&invocation.idempotency_key)
    .bind(&invocation.artifact_id)
    .bind(&entry.id)
    .fetch_optional(&mut *tx)
    .await?;
    let replayed: Option<i64> = match replayed_row {
        None => None,
        Some((event_seq, payload)) => {
            let stored: Value = serde_json::from_str(&payload)?;
            if !facet_guard_context_matches(
                stored.pointer("/origin/alpha_install_guard"),
                &invocation.alpha_install_guard,
            ) {
                return refuse(
                    "idempotency_conflict",
                    "the idempotency key was already used for a different invocation".to_string(),
                );
            }
            Some(event_seq)
        }
    };
    write.before = current_facet_value(&mut tx, &write.record_id, &key, spine).await?;
    if let Some(event_seq) = replayed {
        // A replay commits nothing, so there is no fresh state to describe.
        // The two fields below therefore describe DIFFERENT instants, and that
        // is deliberate rather than an oversight worth unifying:
        //
        // * `before`/`after` report the facet as it stands NOW. If somebody
        //   else has edited it since the original append, that is THEIR value,
        //   not the one this invocation once wrote.
        // * `version` is the token the ORIGINAL append left, in the encoding
        //   this facet is versioned at.
        //
        // The token is deliberately not `current_facet_version` here — that
        // would read back after the gesture and could hand out a token minted
        // by somebody else's later edit, which is precisely the compare-and-set
        // the caller is relying on this token to preserve. If the facet has
        // since moved, this token is stale, and the next invocation that quotes
        // it conflicts rather than overwriting the competing edit. So the
        // mismatched instants fail CLOSED: the pairing can only cost a retry,
        // never a silent overwrite. The two replay tests in
        // `tests/records/artifact_interactions.rs` hold that property, for an
        // open facet and for a spine one.
        //
        // Reconstructing the token from the origin event's seq is sound only
        // because this module appends exactly ONCE per invocation, so that
        // event was the record's newest at the moment it landed;
        // `the_write_path_is_reachable_only_through_a_manifest_entry` enforces
        // it.
        let version = if spine.is_some() {
            FacetVersion::Record { event_seq }
        } else {
            FacetVersion::Observation { event_seq }
        };
        return Ok((
            ArtifactIntentResult::committed(
                &invocation.idempotency_key,
                vec![IntentChange {
                    record_id: write.record_id,
                    key,
                    before: write.before.clone(),
                    after: write.before,
                    version: Some(version.encode()),
                }],
            ),
            act_alloc.get(),
        ));
    }

    // 5. Schema and vocabulary governance on the outgoing value — declared
    //    type, declared `values` set and governing-vocabulary membership, for a
    //    spine key exactly as for an open one — and the required-facet bracket
    //    every other record-writing tool applies. The bracket runs for an unset
    //    too: clearing a required facet is exactly the case it exists to refuse.
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    if !governed.is_empty() {
        if let Err(error) = super::lifecycle::assert_facet_value_predicates_in(
            &mut tx,
            &schema_rows,
            TOOL,
            &record_type,
            record_kind.as_deref(),
            None,
            &mut governed,
        )
        .await
        {
            return refuse("schema_violation", error.to_string());
        }
    }
    let before_required =
        required_violations_in(&mut tx, &schema_rows, &[write.record_id.as_str()]).await?;

    // 7. Compare-and-set, at the granularity each facet actually moves at.
    for (record_id, observed) in &invocation.observed {
        for (observed_key, token) in observed {
            let expected = FacetVersion::parse(token)
                .expect("the envelope validator admitted only host-issued tokens");
            let observed_spine = spine_facet_column(observed_key);
            let issued =
                match (&expected, observed_spine) {
                    (FacetVersion::Observation { event_seq: 0 }, None) => true,
                    (FacetVersion::Observation { event_seq }, None) => {
                        sqlx::query_scalar::<_, bool>(
                            "SELECT EXISTS(SELECT 1 FROM content_events
                          WHERE record_id=? AND seq=?
                            AND type IN ('facet.set','facet.unset')
                            AND json_extract(payload,'$.key')=?)",
                        )
                        .bind(record_id)
                        .bind(event_seq)
                        .bind(observed_key)
                        .fetch_one(&mut *tx)
                        .await?
                    }
                    (FacetVersion::Record { event_seq: 0 }, Some(_)) => {
                        !sqlx::query_scalar::<_, bool>(
                            "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=?)",
                        )
                        .bind(record_id)
                        .fetch_one(&mut *tx)
                        .await?
                    }
                    (FacetVersion::Record { event_seq }, Some(_)) => sqlx::query_scalar::<_, bool>(
                        "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND seq=?)",
                    )
                    .bind(record_id)
                    .bind(event_seq)
                    .fetch_one(&mut *tx)
                    .await?,
                    _ => false,
                };
            if !issued {
                return refuse(
                    "invalid_precondition",
                    format!(
                        "observed version for facet '{observed_key}' on record {record_id} was not issued by the host for that facet"
                    ),
                );
            }
            let current =
                current_facet_version(&mut tx, record_id, observed_key, observed_spine).await?;
            if current != expected {
                let (conflicting_event_id, actor) = conflicting_event_in(
                    &mut tx,
                    record_id,
                    observed_key,
                    &current,
                    observed_spine,
                )
                .await?;
                let competing_actor = match actor.as_deref() {
                    Some(actor) => {
                        super::history::disclosed_actor_identity_in(&mut tx, caller, actor)
                            .await?
                            .map(|(id, display_name)| CompetingActor { id, display_name })
                    }
                    None => None,
                };
                return Ok((
                    ArtifactIntentResult::conflict(
                        &invocation.idempotency_key,
                        IntentError::retryable(
                            "facet_conflict",
                            format!(
                                "facet '{observed_key}' on record {record_id} moved since it was read"
                            ),
                        ),
                        &current,
                        &conflicting_event_id,
                        competing_actor,
                    ),
                    act_alloc.get(),
                ));
            }
        }
    }

    // 8. Commit, attributed to the actor and to the originating artifact.
    // The optional guard authorization context rides along so a replay under a
    // different context conflicts instead of replaying the earlier commit
    // (see the replay branch above). Absent it serializes as an explicit null;
    // a legacy row that predates the field (key missing) reads back as null
    // too, so ordinary unguarded replay is preserved.
    let origin = json!({
        "artifact_id": invocation.artifact_id,
        "entry_id": entry.id,
        "source_digest": invocation.source_digest,
        "idempotency_key": invocation.idempotency_key,
        "gesture": invocation.gesture,
        "alpha_install_guard": serde_json::to_value(&invocation.alpha_install_guard)
            .unwrap_or(Value::Null),
    });
    let mut spec = match (spine, write.value.as_ref()) {
        // Spine facets are record-level field events, not facet events —
        // `record.updated` is how they move everywhere else in the engine, and
        // an artifact interaction must not invent a second way.
        (Some(column), Some(value)) => AppendSpec {
            record_id: write.record_id.clone(),
            event_type: "record.updated".into(),
            payload: json!({
                column: value,
                "reason": format!("Artifact interaction '{}' ({})", entry.id, entry.label),
            }),
            actor: Some(caller.actor().into()),
        },
        (None, Some(_)) => facet_set_spec(
            &write.record_id,
            governed
                .first()
                .expect("a facet.set governs exactly one write"),
            caller.actor(),
        ),
        (None, None) => AppendSpec {
            record_id: write.record_id.clone(),
            event_type: "facet.unset".into(),
            payload: json!({ "key": key }),
            actor: Some(caller.actor().into()),
        },
        (Some(_), None) => unreachable!("spine clears are refused above"),
    };
    if let Some(payload) = spec.payload.as_object_mut() {
        payload.insert("origin".into(), origin);
    }
    let after = write.value.clone();
    append_in(db, &mut tx, spec, &mut act_alloc).await?;
    let after_required =
        required_violations_in(&mut tx, &schema_rows, &[write.record_id.as_str()]).await?;
    if let Err(error) = assert_required_not_worsened(TOOL, &before_required, &after_required) {
        // Dropping the transaction rolls the appended event back with it.
        return refuse("required_facet_missing", error.to_string());
    }
    // The token this write LEFT, read INSIDE the transaction that produced it,
    // before anybody else can append. Computed after the commit it would be a
    // re-read: a competing write could land first and the caller would be
    // handed a token that authorizes overwriting an edit it never saw. Read
    // here, it describes exactly this write and nothing after it.
    //
    // Both mechanisms stay separate, as `current_facet_version` documents: the
    // open facet resolves to the `facet_observations` row this append just
    // projected (`obs:N`), the spine facet to the record event (`rec:N`).
    let version = current_facet_version(&mut tx, &write.record_id, &key, spine).await?;
    // Not a bare `tx.commit()`: content commits issue pending provenance
    // actions, confirm committed attestations, and wake realtime subscribers.
    // A drag that commits durably while no other surface invalidates would
    // defeat the optimistic premise this whole feature rests on.
    db.commit_content(tx).await?;
    Ok((
        ArtifactIntentResult::committed(
            &invocation.idempotency_key,
            vec![IntentChange {
                record_id: write.record_id,
                key,
                before: write.before,
                after,
                version: Some(version.encode()),
            }],
        ),
        act_alloc.get(),
    ))
}

/// Resolve the exact event which produced the current CAS token while the
/// write transaction still holds the state that failed comparison.
async fn conflicting_event_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    key: &str,
    current: &FacetVersion,
    spine: Option<&'static str>,
) -> Result<(String, Option<String>)> {
    let event_seq = if spine.is_some() {
        let FacetVersion::Record { event_seq } = current else {
            return Err(Error::engine(format!(
                "spine facet '{key}' resolved a non-record conflict token"
            )));
        };
        *event_seq
    } else {
        let FacetVersion::Observation { event_seq } = current else {
            return Err(Error::engine(format!(
                "open facet '{key}' resolved a non-observation conflict token"
            )));
        };
        *event_seq
    };
    let row = sqlx::query("SELECT id,actor FROM content_events WHERE record_id=? AND seq=?")
        .bind(record_id)
        .bind(event_seq)
        .fetch_optional(&mut **tx)
        .await?;
    let row = row.ok_or_else(|| {
        Error::engine(format!(
            "facet conflict for '{key}' on record {record_id} has no source event"
        ))
    })?;
    Ok((row.try_get("id")?, row.try_get("actor")?))
}

/// The current compare-and-set token for one facet.
///
/// TWO mechanisms, deliberately, and they are not unified:
///
/// * open facets are versioned by `MAX(event_seq)` over `facet_observations`
///   for that `(record_id, key)` — an index seek on
///   `idx_facet_observations_series`;
/// * spine facets never produce an observation row at all, so their immutable
///   record-wide token is `MAX(content_events.seq)` for the record.
///
/// That is the granularity at which each actually changes, not a shortfall in
/// the spine case.
async fn current_facet_version(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    key: &str,
    spine: Option<&'static str>,
) -> Result<FacetVersion> {
    if spine.is_some() {
        let event_seq: Option<i64> =
            sqlx::query_scalar("SELECT MAX(seq) FROM content_events WHERE record_id=?")
                .bind(record_id)
                .fetch_one(&mut **tx)
                .await?;
        return Ok(FacetVersion::Record {
            event_seq: event_seq.unwrap_or_default(),
        });
    }
    let event_seq: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(event_seq) FROM facet_observations WHERE record_id=? AND key=?",
    )
    .bind(record_id)
    .bind(key)
    .fetch_one(&mut **tx)
    .await?;
    Ok(FacetVersion::Observation {
        event_seq: event_seq.unwrap_or_default(),
    })
}

async fn current_facet_value(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    key: &str,
    spine: Option<&'static str>,
) -> Result<Option<Value>> {
    let stored: Option<Option<String>> = match spine {
        Some(column) => {
            sqlx::query_scalar(&format!("SELECT {column} FROM records WHERE id=?"))
                .bind(record_id)
                .fetch_optional(&mut **tx)
                .await?
        }
        None => {
            sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key=?")
                .bind(record_id)
                .bind(key)
                .fetch_optional(&mut **tx)
                .await?
        }
    };
    Ok(stored.flatten().map(Value::String))
}

/// Register the artifact interaction tool.
pub fn register_artifact_interaction_tool(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::InvokeArtifactInteraction,
        "Run one interaction entry a native.mdx.v2 or native.html.v1 artifact declared in its \
         exact-source manifest. The host validates the source digest, the \
         entry, the slot fillings against their declared domains and the bound \
         input, then authorizes the caller and commits either one facet write \
         with compare-and-set or one governed record creation. The envelope never carries an actor, an \
         authorization or a confirmation.",
        json!({
            "type": "object",
            "properties": {
                "version": {
                    "type": "string",
                    "description": "Envelope version (native.artifact-invocation.v1)."
                },
                "artifact_id": { "type": "string" },
                "entry_id": {
                    "type": "string",
                    "description": "A declared interaction entry id in the artifact's manifest."
                },
                "source_digest": {
                    "type": "string",
                    "description": "SHA-256 of the artifact body this was rendered from."
                },
                "slots": {
                    "type": "object",
                    "description": "Record-domain slot fillings: slot name to record id.",
                    "additionalProperties": { "type": "string" }
                },
                "values": {
                    "type": "object",
                    "description": "Value-domain slot fillings: slot name to value.",
                    "additionalProperties": true
                },
                "observed": {
                    "type": "object",
                    "description": "Compare-and-set preconditions: record id to facet key to the version token get_record issued.",
                    "additionalProperties": {
                        "type": "object",
                        "additionalProperties": { "type": "string" }
                    }
                },
                "idempotency_key": { "type": "string" },
                "gesture": {
                    "type": "string",
                    "description": "What the person did, for provenance only."
                },
                "include_next_plan": {
                    "type": "boolean",
                    "description": "Opt-in: when true and the invocation commits, the result carries the next authoritative render plan under refresh.plan. Omit for the fast receipt."
                },
                "alpha_install_guard": {
                    "type": "object",
                    "description": "Optional exact personal-install guard for a reversible facet intent from an alpha tab. Checked inside the write transaction against the same account's install (installed, verified shell_adopt.v1, generation CAS, exact artifact/source/version/digest/declaration, View, plus consented effects must include task.triage-set.v1) and narrowed to the declared triage facet.set/facet.unset pair on native.html.v1; a manifest interaction or bundle digest alone is never consent and triage consent never authorizes another facet or record.create. Absent, the invocation behaves as before. A refusal names the personal install only and never globally disables the artifact.",
                    "properties": {
                        "package": { "type": "string" },
                        "expected_install_event_id": { "type": "string" },
                        "artifact_id": { "type": "string" },
                        "source_revision": { "type": "string" },
                        "version": { "type": "string" },
                        "digest": { "type": "string" },
                        "declaration_digest": { "type": "string" }
                    },
                    "required": ["package", "expected_install_event_id", "artifact_id", "source_revision", "version", "digest", "declaration_digest"],
                    "additionalProperties": false
                }
            },
            "required": ["version", "artifact_id", "entry_id", "source_digest", "idempotency_key"],
            "additionalProperties": false
        }),
        invoke_artifact_interaction,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("artifact_interactions.rs");

    /// The artifact-runtime crate cannot depend on the engine, so it carries
    /// its own list of keys an artifact may not name. This is the join that
    /// keeps the two honest in both directions: every engine-reserved key must
    /// appear in it, and anything ADDITIONAL must be deliberate rather than
    /// accumulated.
    #[test]
    fn engine_dispatched_facet_keys_cover_the_engine_contract() {
        let dispatched = native_artifact_runtime::mdx_v2::ENGINE_DISPATCHED_FACET_KEYS;
        for reserved in crate::schema::ENGINE_RESERVED_FACET_KEYS {
            assert!(
                dispatched.contains(&reserved),
                "engine-reserved facet '{reserved}' is declarable by an artifact"
            );
        }
        // Reserved is about who may CONFIGURE a key; dispatched is about what
        // the engine DOES with it. `runtime` is an ordinary open facet the
        // engine nonetheless dispatches on, so it is the one deliberate extra.
        let extra = dispatched
            .into_iter()
            .filter(|key| !crate::schema::ENGINE_RESERVED_FACET_KEYS.contains(key))
            .collect::<Vec<_>>();
        assert_eq!(extra, ["runtime"]);
    }

    /// The structural requirement, enforced rather than intended: this module
    /// is the only artifact write path, and inside it every append happens in
    /// `commit_declared_write`, whose signature demands a compiled manifest
    /// entry. Widen either and this test fails.
    #[test]
    fn the_write_path_is_reachable_only_through_a_manifest_entry() {
        // Split the module into top-level items, then insist that every append
        // sits inside the one item whose signature demands a compiled entry.
        let mut items = Vec::new();
        for (offset, _) in SOURCE
            .match_indices("\nasync fn ")
            .chain(SOURCE.match_indices("\nfn "))
        {
            items.push(offset);
        }
        items.sort_unstable();
        let owner = |position: usize| -> &str {
            let start = items
                .iter()
                .rev()
                .find(|item| **item < position)
                .copied()
                .unwrap_or(0);
            let header_end = SOURCE[start..]
                .find('(')
                .map(|offset| start + offset)
                .unwrap_or(SOURCE.len());
            SOURCE[start..header_end].trim()
        };
        // The needles are assembled at runtime so this test does not match its
        // own source text.
        let append = format!("append{}(", "_in");
        let appends = SOURCE.match_indices(append.as_str()).collect::<Vec<_>>();
        assert_eq!(
            appends.len(),
            1,
            "this module appends exactly once — the IDEMPOTENCY-REPLAY branch of \
             `commit_declared_write` RECONSTRUCTS the original write's CAS token from the \
             origin-carrying event's seq rather than measuring it, which is only correct while \
             that event is the newest this path can have produced. A second in-transaction \
             append would make a replayed spine token silently describe an earlier moment than \
             the write it names, so it needs the replay branch reworked, not this count raised."
        );
        for (position, _) in appends {
            assert_eq!(
                owner(position),
                "async fn commit_declared_write",
                "an append appears outside the manifest-entry-taking write path"
            );
        }
        let signature = SOURCE
            .split_once("async fn commit_declared_write(")
            .expect("the entry-taking write function exists")
            .1;
        let (parameters, _) = signature
            .split_once(") -> Result<(ArtifactIntentResult, Option<i64>)> {")
            .expect("the write function has a body");
        assert!(
            parameters.contains("entry: &mdx_v2::InteractionEntry"),
            "the write path must take a compiled manifest entry, not a facet key"
        );
        // The direct store facet setter has no actor and no authorization, so
        // it must not appear anywhere in this module, and neither may a batch
        // append. (Both names are spelled indirectly below for the same reason
        // the append needle is.)
        for forbidden in [
            format!("store::set{}", "_facet"),
            format!("append{}", "_batch"),
        ] {
            assert!(
                !SOURCE.contains(forbidden.as_str()),
                "this module must not reach the store any other way"
            );
        }
    }

    /// The guard authorization context is replay identity, nothing more:
    /// absent (legacy rows predate the key, new unguarded rows store null)
    /// replays only unguarded; a guard replays only its exact pin. Observed,
    /// values and gesture never enter the comparison, so ordinary replay is
    /// not tightened.
    #[test]
    fn facet_guard_context_matches_only_the_identical_guard() {
        use native_artifact_runtime::artifact_intents::AlphaTabInstallGuard;
        let guard_a = || AlphaTabInstallGuard {
            package: "agent.attention-cockpit".into(),
            expected_install_event_id: "evt-1".into(),
            artifact_id: "a".into(),
            source_revision: "evt-src-1".into(),
            version: "0.1.0".into(),
            digest: format!("sha256:{}", "b".repeat(64)),
            declaration_digest: "c".repeat(64),
        };
        let stored_a = serde_json::to_value(guard_a()).unwrap();
        // Legacy rows carry no guard key at all: replayable unguarded, never
        // guarded.
        assert!(facet_guard_context_matches(None, &None));
        assert!(!facet_guard_context_matches(None, &Some(guard_a())));
        // Explicit null (new unguarded rows) behaves identically.
        assert!(facet_guard_context_matches(Some(&Value::Null), &None));
        assert!(!facet_guard_context_matches(
            Some(&Value::Null),
            &Some(guard_a())
        ));
        // Same pin replays; any pin difference conflicts.
        assert!(facet_guard_context_matches(
            Some(&stored_a),
            &Some(guard_a())
        ));
        let mut guard_b = guard_a();
        guard_b.package = "agent.team-pulse".into();
        assert!(!facet_guard_context_matches(
            Some(&stored_a),
            &Some(guard_b)
        ));
        assert!(!facet_guard_context_matches(Some(&stored_a), &None));
    }

    /// The bonus render rides under `refresh` beside the created record a
    /// creation already refreshed — plan, input and digest together, never in
    /// place of the record.
    #[test]
    fn next_plan_merges_with_an_existing_record_refresh() {
        let rendered = json!({
            "status": "rendered",
            "plan": { "kind": "safe_tree" },
            "input": { "records": [] },
            "input_digest": "abc",
        });
        assert_eq!(
            refresh_with_next_plan(None, &rendered),
            Some(json!({
                "plan": { "kind": "safe_tree" },
                "input": { "records": [] },
                "input_digest": "abc",
            }))
        );
        let record = json!({ "record": { "id": "r" } });
        assert_eq!(
            refresh_with_next_plan(Some(&record), &rendered),
            Some(json!({
                "record": { "id": "r" },
                "plan": { "kind": "safe_tree" },
                "input": { "records": [] },
                "input_digest": "abc",
            }))
        );
        // Render fields are forwarded generically: a render that carries no
        // input still yields a plan-only bonus.
        let plan_only = json!({ "status": "rendered", "plan": { "kind": "safe_tree" } });
        assert_eq!(
            refresh_with_next_plan(None, &plan_only),
            Some(json!({ "plan": { "kind": "safe_tree" } }))
        );
        // No plan, no bonus at all — even when the render carries an input.
        let input_only = json!({ "status": "rendered", "input": { "records": [] } });
        assert_eq!(refresh_with_next_plan(None, &input_only), None);
        // A non-object refresh is never produced by this module; if one ever
        // arrives the bonus is dropped rather than mangling it.
        let scalar = json!("already-there");
        assert_eq!(refresh_with_next_plan(Some(&scalar), &rendered), None);
    }

    /// An oversized bonus degrades to the refresh the commit produced on its
    /// own — `None` here means "keep the original", never an invalid result.
    /// All-or-nothing: a plan that fits on its own is still dropped when the
    /// input it needs would breach the cap with it, so the caller never sees
    /// a plan without its input.
    #[test]
    fn an_oversized_next_plan_degrades_to_the_commit_refresh() {
        let oversized = json!({ "tree": "x".repeat(RESULT_REFRESH_JSON_LIMIT) });
        let oversized_rendered = json!({ "status": "rendered", "plan": oversized });
        assert!(refresh_with_next_plan(None, &oversized_rendered).is_none());
        let record = json!({ "record": { "id": "r" } });
        assert!(refresh_with_next_plan(Some(&record), &oversized_rendered).is_none());

        let small_plan = json!({ "kind": "safe_tree" });
        let bulky_input = json!({ "records": ["x".repeat(RESULT_REFRESH_JSON_LIMIT)] });
        let split_breach =
            json!({ "status": "rendered", "plan": small_plan, "input": bulky_input });
        assert!(
            refresh_with_next_plan(None, &split_breach).is_none(),
            "a fitting plan must not survive without its breaching input"
        );
        assert!(
            refresh_with_next_plan(Some(&record), &split_breach).is_none(),
            "all-or-nothing holds beside an existing record refresh too"
        );
    }
}
