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
//! Reversal mode (D7 slice U2b): when the envelope carries `reverses`, the
//! tool reverses the named original invocation instead of running steps 1–5
//! above. Envelope shape (including every reverses rule) is still validated
//! first, and the caller must still see the artifact; then the original is
//! resolved across records, its stored `source_digest` is compared — the
//! current render is never consulted — and the reversal core derives the
//! reverse from history. A reversal carries no package claim: `reverses`
//! with an install guard or any app claim is `invalid_invocation`.
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
use std::sync::OnceLock;

use hmac::{Hmac, Mac};
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

/// Comment-only minimal-receipt projection: omit the shared encode's
/// `refresh: null` placeholder. Only a null refresh is ever removed — a
/// present refresh is preserved (fail-closed) — and shared encode, result
/// shapes, and runtime serde stay untouched.
fn without_null_refresh(mut value: Value) -> Value {
    if value.get("refresh").is_some_and(Value::is_null) {
        value
            .as_object_mut()
            .expect("an intent result always serializes as an object")
            .remove("refresh");
    }
    value
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
    //
    // `reverses`, when present, IS part of the digest for the same reason: a
    // reversal names a different original. Absent, the digest is byte-identical
    // to the pre-reversal shape.
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
    if let Some(reverses) = &invocation.reverses {
        envelope["reverses"] = json!({
            "entry_id": reverses.entry_id,
            "idempotency_key": reverses.idempotency_key,
        });
    }
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

/// Effect-gesture check outcome for one parsed invocation (D7 §4B, slice G2).
pub(super) enum GestureCheck {
    /// No attestation on the caller: the ordinary path.
    Absent,
    /// A valid token: the evidence object to record in the event origin.
    Evidence(Value),
    /// Refused, zero writes.
    Refused {
        code: &'static str,
        message: &'static str,
    },
}

/// The persisted `origin.gesture_evidence` for a verified token. Additive:
/// it is only ever inserted when a token is present, so origins without one
/// stay byte-identical.
pub(super) fn gesture_evidence(kind: crate::awareness::EffectGestureKind) -> Value {
    json!({
        "kind": kind.as_str(),
        "verifier": crate::awareness::EFFECT_GESTURE_VERIFIER,
    })
}

/// Verify the caller's effect-gesture attestation against one exact binding
/// and return the evidence to record (D7 §4B, slice G2). Dormant: with no
/// attestation the result is the ordinary path, byte-identical. A
/// present-but-invalid token is always refused with zero writes, whatever the
/// scope. A *missing* token is refused when full enforcement is on; under the
/// hosted guarded-only scope (G4) it is refused only when `guarded` holds —
/// the invocation carries a package claim, or it is a reversal — and unguarded
/// invocations take the ordinary path unchanged until G5. The binding is
/// action-scoped (`effect.v1` forward, `effect_reversal.v1` for an undo), so a
/// forward token can never satisfy a reversal and vice versa. `artifact_id` is
/// always bound; `values_digest` is the canonical digest of the invocation's
/// value-domain fillings, so a swapped value invalidates the token.
#[allow(clippy::too_many_arguments)] // The binding elements are explicit on purpose; grouping them would hide what is bound.
pub(super) fn verify_effect_gesture(
    caller: &Caller,
    action: &str,
    artifact_id: &str,
    package: Option<(&str, &str)>,
    generation: Option<&str>,
    entry: &str,
    target: &[String],
    idempotency_key: &str,
    values_digest: &str,
    guarded: bool,
) -> GestureCheck {
    let Some(attestation) = caller.effect_gesture() else {
        // Enforcement on and no token: refused before any write, except an
        // unguarded invocation under the hosted guarded-only scope, which
        // stays on the ordinary path. Off (the default), a missing token
        // changes nothing.
        let enforce = caller.effect_gesture_enforcement()
            && (guarded || !caller.effect_gesture_enforcement_guarded_only());
        return if enforce {
            GestureCheck::Refused {
                code: "gesture_attestation_required",
                message: "this deployment requires an effect gesture token for this invocation",
            }
        } else {
            GestureCheck::Absent
        };
    };
    let ids = crate::awareness::effect_gesture_binding_ids(
        caller.credential(),
        artifact_id,
        package,
        generation,
        entry,
        target,
        idempotency_key,
        values_digest,
        attestation.kind(),
    );
    if attestation
        .verify(caller.credential(), action, &ids)
        .is_err()
    {
        return GestureCheck::Refused {
            code: "gesture_attestation_invalid",
            message: "the effect gesture token does not match this invocation, or it expired",
        };
    }
    GestureCheck::Evidence(gesture_evidence(attestation.kind()))
}

/// Canonical digest of an invocation's value-domain fillings, bound into the
/// effect-gesture token so a swapped value cannot ride a valid token.
/// Shared with the hosted adapter through
/// [`crate::awareness::effect_gesture_values_digest`].
pub(super) fn invocation_values_digest(invocation: &ArtifactInvocation) -> String {
    crate::awareness::effect_gesture_values_digest(
        &serde_json::to_value(&invocation.values).unwrap_or(Value::Null),
    )
}

/// The forward binding for a parsed invocation: package from the alpha guard,
/// artifact, entry and key from the envelope, target the record-domain slot
/// ids, and the values digest. An unguarded artifact (no `alpha_install_guard`,
/// e.g. a Workbench artifact before G5) binds `pkg`/`gen` absent; its token
/// still binds viewer, artifact, entry, target, values, key and gesture, which
/// is the whole invocation it authorizes.
fn check_effect_gesture(caller: &Caller, invocation: &ArtifactInvocation) -> GestureCheck {
    let package = invocation
        .alpha_install_guard
        .as_ref()
        .map(|guard| ("alpha", guard.package.as_str()));
    let generation = invocation
        .alpha_install_guard
        .as_ref()
        .map(|guard| guard.expected_install_event_id.as_str());
    let target = invocation.slots.values().cloned().collect::<Vec<_>>();
    // Reversals dispatch before this check; the forward scope is the package
    // claim (any future app claim widens this alongside the mint condition).
    let guarded = invocation.alpha_install_guard.is_some();
    verify_effect_gesture(
        caller,
        crate::awareness::EFFECT_GESTURE_ACTION,
        &invocation.artifact_id,
        package,
        generation,
        &invocation.entry_id,
        &target,
        &invocation.idempotency_key,
        &invocation_values_digest(invocation),
        guarded,
    )
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

/// The classifier's verdict for the entry an invocation cites, read from the
/// actual immutable source bytes for its requested digest — never from an
/// attestation descriptor alone, a guard, a compare-and-set token, or today's
/// facet. Task `b9fb9fd` family 1: this only decides whether the legacy
/// `record.create` replay may run. It grants no authority, and it is not a
/// confirmation step.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CitedEntryClass {
    /// The cited entry is a `comment.create` declaration.
    Comment,
    /// The cited entry is a `message.react` declaration.
    React,
    /// The cited entry is a `title.set` declaration.
    Title,
    /// Body citation must not consult legacy creation replay.
    Body,
    /// The cited entry is a verified non-comment, non-react declaration.
    Other,
    /// No exact immutable or exact-current body proves the cited entry. No
    /// history may be surfaced for this invocation.
    Unresolved,
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Read one immutable body-bearing event out of `content_events`, restricted
/// to the same event types artifact resolution treats as carrying a body. The
/// `payload` column is nullable TEXT with no `json_valid` CHECK, so malformed
/// JSON must read as absent — never as an error a caller could distinguish
/// from a missing row. A blanket catch would also hide real IO faults, so the
/// extraction stays guarded by `json_valid` in SQL.
async fn body_of_event(db: &Db, artifact_id: &str, event_id: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT CASE WHEN json_valid(payload) THEN
                    CASE WHEN json_type(payload,'$.body')='text'
                         THEN json_extract(payload,'$.body') END
                  END
           FROM content_events
          WHERE record_id=? AND id=?
            AND type IN ('record.created','record.updated','receipt.committed.v1')
          LIMIT 1",
    )
    .bind(artifact_id)
    .bind(event_id)
    .fetch_optional(db.pool())
    .await?
    .flatten())
}

/// The current artifact body event, read directly rather than through artifact
/// resolution so a resolution diagnostic can never supersede an exact
/// historical classification.
async fn current_artifact_body(db: &Db, artifact_id: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT CASE WHEN json_valid(payload) THEN
                    CASE WHEN json_type(payload,'$.body')='text'
                         THEN json_extract(payload,'$.body') END
                  END
           FROM content_events
          WHERE record_id=?
            AND type IN ('record.created','record.updated','receipt.committed.v1')
            AND CASE WHEN json_valid(payload)
                     THEN json_type(payload,'$.body')='text'
                     ELSE 0 END
          ORDER BY seq DESC LIMIT 1",
    )
    .bind(artifact_id)
    .fetch_optional(db.pool())
    .await?
    .flatten())
}

async fn current_artifact_runtime(db: &Db, artifact_id: &str) -> Result<Option<String>> {
    Ok(sqlx::query_scalar::<_, Option<String>>(
        "SELECT value FROM facet_values WHERE record_id=? AND key='runtime'",
    )
    .bind(artifact_id)
    .fetch_optional(db.pool())
    .await?
    .flatten())
}

/// Every attested source event is at most one runtime-aware parser away. The
/// descriptor carries the runtime only for `native.html.v1`; MDX descriptors
/// keep their established byte shape and default to the v2 parser.
async fn attested_source(
    db: &Db,
    artifact_id: &str,
    source_sha256: &str,
) -> Result<Option<(String, Option<String>)>> {
    let row = sqlx::query(
        "SELECT source_event_id, descriptor
           FROM artifact_source_attestations
          WHERE artifact_id=? AND source_sha256=?
          ORDER BY event_seq DESC LIMIT 1",
    )
    .bind(artifact_id)
    .bind(source_sha256)
    .fetch_optional(db.pool())
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let source_event_id: String = row.try_get("source_event_id")?;
    let runtime = row
        .try_get::<String, _>("descriptor")
        .ok()
        .and_then(|descriptor| serde_json::from_str::<Value>(&descriptor).ok())
        .and_then(|descriptor| {
            descriptor
                .get("runtime")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    Ok(Some((source_event_id, runtime)))
}

/// The runtime a source event's own attestation recorded, when one exists.
/// Deliberately distinct from today's facet: an old source is parsed with the
/// runtime it was compiled under, never the artifact's current runtime.
async fn attested_runtime_for_event(
    db: &Db,
    artifact_id: &str,
    event_id: &str,
) -> Result<Option<String>> {
    let descriptor: Option<String> = sqlx::query_scalar(
        "SELECT descriptor FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=? LIMIT 1",
    )
    .bind(artifact_id)
    .bind(event_id)
    .fetch_optional(db.pool())
    .await?;
    Ok(descriptor
        .and_then(|descriptor| serde_json::from_str::<Value>(&descriptor).ok())
        .and_then(|descriptor| {
            descriptor
                .get("runtime")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }))
}

/// The bounded legacy candidate an old replay could act on: same actor,
/// artifact, entry and idempotency key, with no effect discriminator. Its own
/// origin carries the immutable source pointer and digest. Absent `effect`
/// rows (including forged comment origins) prove nothing.
async fn legacy_candidate_source(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
) -> Result<Option<(String, String)>> {
    let payload: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events
          WHERE type='record.created' AND actor=?
            AND CASE WHEN json_valid(payload)
                     THEN json_extract(payload,'$.origin.artifact_id')=? END
            AND CASE WHEN json_valid(payload)
                     THEN json_extract(payload,'$.origin.entry_id')=? END
            AND CASE WHEN json_valid(payload)
                     THEN json_extract(payload,'$.origin.idempotency_key')=? END
            AND CASE WHEN json_valid(payload)
                     THEN (json_extract(payload,'$.origin.effect') IS NULL)
                     ELSE 0 END
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&invocation.artifact_id)
    .bind(&invocation.entry_id)
    .bind(&invocation.idempotency_key)
    .fetch_optional(db.pool())
    .await?;
    let Some(payload) = payload else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<Value>(&payload) else {
        return Ok(None);
    };
    let origin = value.get("origin");
    let event_id = origin
        .and_then(|origin| origin.get("source_event_id"))
        .and_then(Value::as_str);
    let digest = origin
        .and_then(|origin| origin.get("source_digest"))
        .and_then(Value::as_str);
    match (event_id, digest) {
        (Some(event_id), Some(digest)) => Ok(Some((event_id.to_owned(), digest.to_owned()))),
        _ => Ok(None),
    }
}

/// Parse an actual source body with the existing bounded parsers and report
/// the cited entry's effect. The runtime hint only prioritizes which parser
/// runs first: an absent or stale hint must not stop a valid MDX or HTML body
/// from being classified, and it is never taken from today's facet for a
/// historical source. An ordinary validation failure reads as unverified
/// (`None`); a terminated compiler worker is an infrastructure fault and
/// propagates.
async fn cited_entry_effect(
    body: String,
    runtime: Option<&str>,
    entry_id: &str,
    partition: &str,
) -> Result<Option<InteractionEffect>> {
    let order = if runtime == Some(crate::artifact_html::RUNTIME_ID) {
        [crate::artifact_html::RUNTIME_ID, mdx_v2::RUNTIME_ID]
    } else {
        [mdx_v2::RUNTIME_ID, crate::artifact_html::RUNTIME_ID]
    };
    for candidate in order {
        if candidate == crate::artifact_html::RUNTIME_ID {
            if let Ok(manifest) = crate::artifact_html::validate_cached(&body) {
                if let Some(entry) = manifest.interaction_manifest().interaction(entry_id) {
                    return Ok(Some(entry.effect));
                }
            }
        } else {
            let source = body.clone();
            let partition = partition.to_owned();
            let parsed = tokio::task::spawn_blocking(move || {
                mdx_v2::parse_artifact_cached(&source, &partition)
            })
            .await
            .map_err(|_| Error::engine(format!("{TOOL}: artifact compiler worker terminated")))?;
            if let Ok((parsed, _cache_state)) = parsed {
                if let mdx_v2::Manifest::Artifact(manifest) = parsed.manifest {
                    if let Some(entry) = manifest.interaction(entry_id) {
                        return Ok(Some(entry.effect));
                    }
                }
            }
        }
    }
    Ok(None)
}

fn classify_effect(effect: InteractionEffect) -> CitedEntryClass {
    if effect == InteractionEffect::CommentCreate {
        // Positive cited Comment: server-derived DomainOwned immediately,
        // never reset. Consumes the registry's existing pub(crate) seam.
        crate::mcp::registry::note_invoke_domain_owned();
        CitedEntryClass::Comment
    } else if effect == InteractionEffect::MessageReact {
        // Positive cited React: same DomainOwned treatment, and the legacy
        // `record.create` replay below stays closed to it.
        crate::mcp::registry::note_invoke_domain_owned();
        CitedEntryClass::React
    } else if effect == InteractionEffect::TitleSet {
        // Positive cited Title: same DomainOwned treatment, and the legacy
        // `record.create` replay below stays closed to it.
        crate::mcp::registry::note_invoke_domain_owned();
        CitedEntryClass::Title
    } else if effect == InteractionEffect::BodySet {
        crate::mcp::registry::note_invoke_domain_owned();
        CitedEntryClass::Body
    } else {
        CitedEntryClass::Other
    }
}

/// Tri-state classification of the entry an invocation cites, before the
/// legacy creation replay runs. Order:
///
/// 1. the exact attested immutable body for the requested digest;
/// 2. the current body, but only when its actual SHA equals the requested one
///    (an exact source proof, not a stale-source heuristic);
/// 3. the bounded legacy candidate's own immutable origin, where only an
///    exact SHA match plus a `record.create` entry enables the unchanged
///    legacy replay.
///
/// A malformed, forged, missing or different-source candidate resolves to
/// `Unresolved`, whose ordinary outcome is identical to an absent candidate.
async fn classify_cited_entry(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
) -> Result<CitedEntryClass> {
    let partition = caller.hosting_principal().unwrap_or("local").to_owned();
    if let Some((event_id, runtime)) =
        attested_source(db, &invocation.artifact_id, &invocation.source_digest).await?
    {
        if let Some(body) = body_of_event(db, &invocation.artifact_id, &event_id).await? {
            if sha256_hex(body.as_bytes()) == invocation.source_digest {
                if let Some(effect) =
                    cited_entry_effect(body, runtime.as_deref(), &invocation.entry_id, &partition)
                        .await?
                {
                    return Ok(classify_effect(effect));
                }
            }
        }
    }
    if let Some(body) = current_artifact_body(db, &invocation.artifact_id).await? {
        if sha256_hex(body.as_bytes()) == invocation.source_digest {
            let runtime = current_artifact_runtime(db, &invocation.artifact_id).await?;
            if let Some(effect) =
                cited_entry_effect(body, runtime.as_deref(), &invocation.entry_id, &partition)
                    .await?
            {
                return Ok(classify_effect(effect));
            }
        }
    }
    if let Some((event_id, digest)) = legacy_candidate_source(db, caller, invocation).await? {
        if digest == invocation.source_digest {
            if let Some(body) = body_of_event(db, &invocation.artifact_id, &event_id).await? {
                if sha256_hex(body.as_bytes()) == invocation.source_digest {
                    let runtime =
                        attested_runtime_for_event(db, &invocation.artifact_id, &event_id).await?;
                    if let Some(effect) = cited_entry_effect(
                        body,
                        runtime.as_deref(),
                        &invocation.entry_id,
                        &partition,
                    )
                    .await?
                    {
                        if effect == InteractionEffect::RecordCreate {
                            return Ok(CitedEntryClass::Other);
                        }
                    }
                }
            }
        }
    }
    Ok(CitedEntryClass::Unresolved)
}

async fn replayed_creation(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    digest: &str,
) -> Result<Option<Value>> {
    // Future comment origins carry an explicit `effect: 'comment.create'`
    // discriminator; legacy origins omit it. Exclude comment rows here so a
    // new comment arm can never reuse an unrelated old replay — while rows
    // without the discriminator keep their exact replay behavior. The
    // comment write path uses its own post-authorization replay later.
    let row = sqlx::query(
        "SELECT record_id,payload,act FROM content_events
          WHERE type='record.created' AND actor=?
            AND CASE WHEN json_valid(payload)
                     THEN json_extract(payload,'$.origin.artifact_id')=? END
            AND CASE WHEN json_valid(payload)
                     THEN json_extract(payload,'$.origin.entry_id')=? END
            AND CASE WHEN json_valid(payload)
                     THEN json_extract(payload,'$.origin.idempotency_key')=? END
            AND CASE WHEN json_valid(payload)
                     THEN (json_extract(payload,'$.origin.effect') IS NULL)
                     ELSE 0 END
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

/// Comment target-state tokens (`ct:`), task `b9fb9fd` family 1.
///
/// A token seals the parent thread's authoritative state at render time so a
/// later write can tell a stale parent (conflict) from concurrent child
/// appends, which carry their own record ids and leave the parent
/// untouched. Tokens are opaque: no sequence, no account, no revision text
/// crosses the bridge in a token, an error, or metadata.
///
/// The process key rotates on restart, which invalidates outstanding tokens
/// and sends the holder back to re-read — the same fail-closed outcome as
/// any other stale precondition. No install-generation scope enters the
/// token; exact install freshness stays a separate write-transaction gate.
///
/// Reads only: nothing in this section mutates the log, so the write-path
/// tripwire below keeps holding. The same helpers run on the governed
/// render snapshot (mint) and, in the posting increment, on the write
/// transaction (compare) — both take the caller's transaction rather than
/// opening their own pool or snapshot.
/// Authoritative parent-thread state sealed into a comment token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommentParentState {
    /// `MAX(seq)` over the parent's content events: the record-specific
    /// revision. Any edit to the parent moves it; nothing else may mint it.
    pub revision_seq: i64,
    /// The opaque event id at that revision, for conflict attribution.
    /// Never a raw sequence, never synthesized: `None` parentage (unknown,
    /// deleted, or revision-less) fails closed at the reader below.
    pub revision_event_id: String,
    pub record_type: String,
    pub kind: Option<String>,
    pub lifecycle: Option<String>,
    pub home_id: Option<String>,
    /// Sorted `part_of` targets: the thread-structure half of the state.
    pub part_of: Vec<String>,
}

/// Read one parent's live state on the caller's governed transaction.
/// `Ok(None)` for an unknown, deleted, or revision-less parent — the
/// caller refuses, never fabricates. Callers pass viewer-scoped cohorts;
/// authority is re-proved on the write snapshot, never carried from here.
pub(crate) async fn read_comment_parent_state_in(
    tx: &mut Transaction<'_, Sqlite>,
    target: &str,
) -> Result<Option<CommentParentState>> {
    let row = sqlx::query(
        "SELECT type, kind, lifecycle, home_id FROM records WHERE id=? AND deleted_at IS NULL",
    )
    .bind(target)
    .fetch_optional(&mut **tx)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let revision: Option<(i64, String)> = sqlx::query_as(
        "SELECT seq, id FROM content_events WHERE record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(target)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((revision_seq, revision_event_id)) = revision else {
        return Ok(None);
    };
    let part_of: Vec<String> = sqlx::query_scalar(
        "SELECT target_id FROM links
          WHERE source_id=? AND relationship='part_of'
          ORDER BY target_id",
    )
    .bind(target)
    .fetch_all(&mut **tx)
    .await?;
    Ok(Some(CommentParentState {
        revision_seq,
        revision_event_id,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        lifecycle: row.try_get("lifecycle")?,
        home_id: row.try_get("home_id")?,
        part_of,
    }))
}

/// What the render path seals into each comment token. Every field comes
/// from the live render transaction's own resolution — the viewer, the
/// artifact, and the exact resolved source — never caller claims and never
/// a parse cache.
pub(crate) struct CommentMintContext<'a> {
    pub caller_credential: &'a str,
    pub artifact_id: &'a str,
    pub source_event_id: &'a str,
    pub source_digest: &'a str,
}

/// Seal one comment token with an explicit key. Pure and vector-testable:
/// field order is part of the token (caller credential, artifact, source
/// event plus hash, target, then the parent snapshot), and every field is
/// length-prefixed so concatenations cannot collide.
pub(crate) fn seal_comment_token_with_key(
    key: &[u8; 32],
    context: &CommentMintContext<'_>,
    target: &str,
    state: &CommentParentState,
) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("fixed process key length");
    let mut part = |text: &str| {
        mac.update(&(text.len() as u64).to_be_bytes());
        mac.update(text.as_bytes());
    };
    part(context.caller_credential);
    part(context.artifact_id);
    part(context.source_event_id);
    part(context.source_digest);
    part(target);
    part(&state.revision_seq.to_string());
    part(&state.revision_event_id);
    part(&state.record_type);
    part(state.kind.as_deref().unwrap_or(""));
    part(state.lifecycle.as_deref().unwrap_or(""));
    part(state.home_id.as_deref().unwrap_or(""));
    for bearer in &state.part_of {
        part(bearer);
    }
    let digest = mac.finalize().into_bytes();
    format!(
        "{}{}",
        native_artifact_runtime::artifact_intents::COMMENT_TOKEN_PREFIX,
        hex::encode(&digest[..16])
    )
}

/// The process CSPRNG key tokens are sealed with. Rotation on restart
/// invalidates outstanding tokens fail-closed.
fn comment_token_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(rand::random::<[u8; 32]>)
}

/// Seal one comment token with the process key, for the render path (and,
/// in the posting increment, the write-transaction recomputation).
pub(crate) fn seal_comment_token(
    context: &CommentMintContext<'_>,
    target: &str,
    state: &CommentParentState,
) -> String {
    seal_comment_token_with_key(comment_token_key(), context, target, state)
}

/// Constant-time comparison of a presented token against expected raw
/// bytes. Malformed input is simply unequal — never an error, never a
/// leak about which half failed.
pub(crate) fn verify_comment_token(presented: &str, expected: &[u8; 16]) -> bool {
    use native_artifact_runtime::artifact_intents::parse_comment_token;
    let Some(bytes) = parse_comment_token(presented) else {
        return false;
    };
    let mut diff = 0u8;
    for (actual, wanted) in bytes.iter().zip(expected.iter()) {
        diff |= actual ^ wanted;
    }
    diff == 0
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

#[allow(clippy::too_many_arguments)] // Manifest, source and gesture pins stay explicit at the write boundary.
async fn invoke_record_create(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
    invocation_digest: &str,
    gesture_evidence: Option<Value>,
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
        gesture_evidence,
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

/// Compose a private comment plan from a resolved invocation. Every
/// identity is engine-derived: the guard must be present (comments are
/// consent-gated, no unguarded path), its artifact and source revision pin
/// the plan, the entry comes from the exact cited source (resolved by the
/// caller, never frame JSON), and slots plus values must name exactly the
/// declared bearer slot and body input — nothing more. Failures are
/// rejections with existing refusal shapes, never authority.
async fn compose_comment_plan(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
) -> Result<std::result::Result<super::lifecycle::ArtifactCommentPlan, (String, String)>> {
    let reject = |code: &str, message: String| (code.to_string(), message);
    let Some(guard) = &invocation.alpha_install_guard else {
        return Ok(Err(reject(
            "alpha_guard_required",
            "comment.create requires a personal-install guard; unguarded comment posting is not admitted".to_string(),
        )));
    };
    if guard.artifact_id != invocation.artifact_id {
        return Ok(Err(reject(
            "alpha_guard_artifact_mismatch",
            "the install guard names a different artifact than the invocation".to_string(),
        )));
    }
    if source_event_id != guard.source_revision {
        return Ok(Err(reject(
            "alpha_guard_source_mismatch",
            "the comment plan source must be the guard's pinned source revision".to_string(),
        )));
    }
    let Some(comment) = entry.comment.as_ref() else {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "comment.create entry '{}' declares no comment envelope",
                entry.id
            ),
        )));
    };
    let position = match comment.position {
        mdx_v2::CommentPosition::Root => "root",
        mdx_v2::CommentPosition::Reply => "reply",
    };
    // Exactly the declared bearer slot and body input: missing fillings
    // cannot post, and extra fillings cannot smuggle scope.
    if entry.slots.len() != 1 {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "comment.create entry '{}' declares no single bearer slot",
                entry.id
            ),
        )));
    }
    let (bearer_slot, bearer_decl) = entry.slots.iter().next().expect("checked");
    if bearer_slot == &comment.body.input {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "comment.create entry '{}' reuses its bearer slot as the body input",
                entry.id
            ),
        )));
    }
    let Some(bearer_id) = invocation.slots.get(bearer_slot).cloned() else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("bearer slot '{bearer_slot}' is unfilled"),
        )));
    };
    if let Some(extra) = invocation
        .slots
        .keys()
        .find(|name| *name != bearer_slot)
        .or_else(|| {
            invocation
                .values
                .keys()
                .find(|name| *name != &comment.body.input)
        })
    {
        return Ok(Err(reject(
            "unknown_slot",
            format!("entry '{}' declares no slot '{extra}'", entry.id),
        )));
    }
    let Some(body) = invocation.values.get(&comment.body.input) else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("entry '{}' needs its declared body", entry.id),
        )));
    };
    let Some(body) = body.as_str() else {
        return Ok(Err(reject(
            "value_outside_domain",
            format!(
                "value for comment body '{}' is outside its declared domain",
                comment.body.input
            ),
        )));
    };
    // Candidate binding scope from the entry's explicit port, re-proved on
    // the write transaction before any replay or append. Mirrors the facet
    // pre-transaction derivation; revocation or rebinding fails there.
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
        Err(diagnostic) => {
            return Ok(Err((
                diagnostic
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("named_input_unbound")
                    .to_string(),
                diagnostic
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("the comment bearer port is not bound")
                    .to_string(),
            )))
        }
    };
    let Some(port) = (match &bearer_decl.domain {
        SlotDomain::BoundInput { port } => port.clone(),
        SlotDomain::Values { .. } => None,
    }) else {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "comment.create entry '{}' declares no explicit bearer port",
                entry.id
            ),
        )));
    };
    let Some(bound) = ports
        .iter()
        .find(|bound| bound.port == port && bound.writable_records && bound.root_readable)
    else {
        return Ok(Err(reject(
            "named_input_unbound",
            format!("bearer input port '{port}' is not bound to a readable Collection"),
        )));
    };
    let observed_token = invocation
        .observed
        .get(&bearer_id)
        .and_then(|keys| keys.get(native_artifact_runtime::artifact_intents::COMMENT_TARGET_KEY))
        .cloned();
    Ok(Ok(super::lifecycle::ArtifactCommentPlan {
        artifact_id: invocation.artifact_id.clone(),
        entry_id: entry.id.clone(),
        entry: entry.clone(),
        source_event_id: source_event_id.to_owned(),
        source_digest: invocation.source_digest.clone(),
        target_id: bearer_id,
        position: position.to_string(),
        body: body.to_string(),
        manifest_max_bytes: comment.body.max_bytes,
        scope_port: bound.port.clone(),
        scope_collection_id: bound.collection_id.clone(),
        scope_kind: bound.kind.clone(),
        observed_token,
        idempotency_key: invocation.idempotency_key.clone(),
        gesture: invocation.gesture.clone(),
        guard: guard.clone(),
        // Admission metadata is resolved fresh by the comment kernel at its
        // install guard stage (D7 §4C.2 N3c); composition carries none.
        resolved_admission: None,
        gesture_evidence: None,
    }))
}

/// Compose the fixed react plan from the parsed entry and the invocation.
/// Exactly the declared message slot and the fixed `emoji`/`reacted`
/// values: missing fillings cannot react, and extra fillings cannot
/// smuggle scope. The emoji must sit inside the manifest subset; the
/// consented subset is re-proved in-transaction. No frame CAS is accepted.
async fn compose_react_plan(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
) -> Result<std::result::Result<super::lifecycle::ArtifactReactPlan, (String, String)>> {
    let reject = |code: &str, message: String| (code.to_string(), message);
    let Some(guard) = &invocation.alpha_install_guard else {
        return Ok(Err(reject(
            "alpha_guard_required",
            "message.react requires a personal-install guard; unguarded reactions are not admitted"
                .to_string(),
        )));
    };
    if guard.artifact_id != invocation.artifact_id {
        return Ok(Err(reject(
            "alpha_guard_artifact_mismatch",
            "the install guard names a different artifact than the invocation".to_string(),
        )));
    }
    if source_event_id != guard.source_revision {
        return Ok(Err(reject(
            "alpha_guard_source_mismatch",
            "the react plan source must be the guard's pinned source revision".to_string(),
        )));
    }
    let Some(react) = entry.react.as_ref() else {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "message.react entry '{}' declares no react envelope",
                entry.id
            ),
        )));
    };
    if entry.slots.len() != 1 {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "message.react entry '{}' declares no single message slot",
                entry.id
            ),
        )));
    }
    let (message_slot, message_decl) = entry.slots.iter().next().expect("checked");
    let Some(message_id) = invocation.slots.get(message_slot).cloned() else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("message slot '{message_slot}' is unfilled"),
        )));
    };
    if message_id.trim().is_empty() {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("message slot '{message_slot}' is blank"),
        )));
    }
    if let Some(extra) = invocation.slots.keys().find(|name| *name != message_slot) {
        return Ok(Err(reject(
            "unknown_slot",
            format!("entry '{}' declares no slot '{extra}'", entry.id),
        )));
    }
    let Some(emoji) = invocation.values.get("emoji").and_then(Value::as_str) else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("entry '{}' needs its emoji value", entry.id),
        )));
    };
    let emoji = emoji.to_string();
    let Some(reacted) = invocation.values.get("reacted").and_then(Value::as_bool) else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("entry '{}' needs its reacted value", entry.id),
        )));
    };
    if let Some(extra) = invocation
        .values
        .keys()
        .find(|name| name.as_str() != "emoji" && name.as_str() != "reacted")
    {
        return Ok(Err(reject(
            "unknown_slot",
            format!("entry '{}' declares no value '{extra}'", entry.id),
        )));
    }
    if !react.emoji.iter().any(|allowed| allowed == &emoji) {
        return Ok(Err(reject(
            "invalid_declaration",
            "react emoji is outside the entry's declared subset".to_string(),
        )));
    }
    // Candidate binding scope from the entry's explicit port, re-proved on
    // the write transaction before any replay or append. Mirrors the facet
    // pre-transaction derivation; revocation or rebinding fails there.
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
        Err(diagnostic) => {
            return Ok(Err((
                diagnostic
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("named_input_unbound")
                    .to_string(),
                diagnostic
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("the react message port is not bound")
                    .to_string(),
            )))
        }
    };
    let Some(port) = (match &message_decl.domain {
        SlotDomain::BoundInput { port } => port.clone(),
        SlotDomain::Values { .. } => None,
    }) else {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "message.react entry '{}' declares no explicit message port",
                entry.id
            ),
        )));
    };
    let Some(bound) = ports
        .iter()
        .find(|bound| bound.port == port && bound.writable_records && bound.root_readable)
    else {
        return Ok(Err(reject(
            "named_input_unbound",
            format!("message input port '{port}' is not bound to a readable Collection"),
        )));
    };
    Ok(Ok(super::lifecycle::ArtifactReactPlan {
        artifact_id: invocation.artifact_id.clone(),
        entry_id: entry.id.clone(),
        entry: entry.clone(),
        source_event_id: source_event_id.to_owned(),
        source_digest: invocation.source_digest.clone(),
        message_id,
        emoji,
        adding: reacted,
        scope_port: bound.port.clone(),
        scope_collection_id: bound.collection_id.clone(),
        scope_kind: bound.kind.clone(),
        idempotency_key: invocation.idempotency_key.clone(),
        gesture: invocation.gesture.clone(),
        guard: guard.clone(),
        // Admission metadata is resolved fresh by the reaction kernel at its
        // install guard stage (D7 §4C.2 N3c); composition carries none.
        resolved_admission: None,
        gesture_evidence: None,
    }))
}

/// Private canonical comment dispatch, task `b9fb9fd` family 1. Composes
/// the plan, runs it through the ordinary canonical kernel, and maps the
/// typed outcome to intent results. Wired on the public native.html.v1 path
/// only; MDX comment invocation remains `comment_unavailable`.
async fn invoke_comment_create(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
    gesture_evidence: Option<Value>,
) -> Result<Value> {
    let mut plan =
        match compose_comment_plan(db, caller, invocation, entry, manifest, source_event_id).await?
        {
            Ok(plan) => plan,
            Err((code, message)) => return Ok(rejected(invocation, &code, message)),
        };
    plan.gesture_evidence = gesture_evidence;
    // The wrapper builds its own fixed arguments from the plan: no frame
    // fields, home, or origin cross this boundary.
    let outcome =
        super::lifecycle::create_comment_from_artifact(db.clone(), caller.clone(), plan).await?;
    match outcome {
        super::lifecycle::ArtifactCommentOutcome::Created(receipt)
        | super::lifecycle::ArtifactCommentOutcome::Replayed(receipt) => {
            let changes = vec![IntentChange {
                record_id: receipt
                    .get("comment_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                key: "comment".to_string(),
                before: None,
                after: Some(serde_json::json!({
                    "created": true,
                    "bearer_id": receipt.get("bearer_id"),
                    "position": receipt.get("position"),
                })),
                version: None,
            }];
            Ok(without_null_refresh(encode(
                ArtifactIntentResult::committed(&invocation.idempotency_key, changes),
            )))
        }
        super::lifecycle::ArtifactCommentOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } => Ok(without_null_refresh(encode(
            ArtifactIntentResult::Conflict {
                version: native_artifact_runtime::artifact_intents::INTENT_RESULT_VERSION.into(),
                idempotency_key: invocation.idempotency_key.clone(),
                error: IntentError::retryable(
                    "comment_conflict",
                    "the comment thread moved since it was read; re-read the thread and retry",
                ),
                current_version,
                conflicting_event_id,
                competing_actor: None,
                refresh: None,
            },
        ))),
        super::lifecycle::ArtifactCommentOutcome::Refused { code, message } => {
            Ok(rejected(invocation, &code, message))
        }
    }
}

/// Private canonical react dispatch, task `07ae879` I2. Composes the plan,
/// runs it through the governed reaction kernel, and maps the typed
/// outcome to intent results with the minimal receipt. Wired on the public
/// native.html.v1 path only; MDX react invocation remains
/// `react_unavailable`. Never touches acknowledgement state.
async fn invoke_message_react(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
    gesture_evidence: Option<Value>,
) -> Result<Value> {
    let plan =
        match compose_react_plan(db, caller, invocation, entry, manifest, source_event_id).await? {
            Ok(mut plan) => {
                plan.gesture_evidence = gesture_evidence;
                plan
            }
            Err((code, message)) => return Ok(rejected(invocation, &code, message)),
        };
    // The wrapper builds its own fixed arguments from the plan: no frame
    // fields or origin cross this boundary.
    match super::lifecycle::react_to_message_from_artifact(db.clone(), caller.clone(), plan).await?
    {
        super::lifecycle::ArtifactReactOutcome::Committed { receipt } => {
            let changes = vec![IntentChange {
                record_id: receipt
                    .get("message_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                key: "reaction".to_string(),
                before: None,
                after: Some(receipt),
                version: None,
            }];
            Ok(without_null_refresh(encode(
                ArtifactIntentResult::committed(&invocation.idempotency_key, changes),
            )))
        }
        super::lifecycle::ArtifactReactOutcome::Refused { code, message } => {
            Ok(rejected(invocation, &code, message))
        }
    }
}

async fn compose_body_plan(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
) -> Result<super::lifecycle::ArtifactBodySavePlan> {
    invocation
        .validate_shape()
        .map_err(|_| Error::engine("body invalid invocation"))?;
    require_record(db, caller, TOOL, &invocation.artifact_id, Capability::View).await?;
    let runtime = current_artifact_runtime(db, &invocation.artifact_id).await?;
    let guard = invocation
        .alpha_install_guard
        .as_ref()
        .ok_or_else(|| Error::engine("body alpha guard required"))?;
    if runtime.as_deref() != Some(crate::artifact_html::RUNTIME_ID)
        || guard.artifact_id != invocation.artifact_id
        || guard.source_revision != source_event_id
        || entry.effect != InteractionEffect::BodySet
        || manifest.interaction(&entry.id) != Some(entry)
        || entry.id != invocation.entry_id
        || entry.body.is_none()
        || entry.slots.len() != 1
        || !invocation.observed.is_empty()
        || invocation.reverses.is_some()
        || invocation.include_next_plan
        || invocation.values.len() != 2
        || invocation.slots.len() != 1
    {
        return Err(Error::engine("body invalid declaration or envelope"));
    }
    let (slot, declaration) = entry
        .slots
        .iter()
        .next()
        .ok_or_else(|| Error::engine("body record slot"))?;
    if !matches!(&declaration.domain, SlotDomain::BoundInput { port: Some(port) } if !port.is_empty() && port != "default")
        || !invocation.slots.contains_key(slot)
        || invocation
            .values
            .get("body")
            .and_then(Value::as_str)
            .is_none()
        || invocation
            .values
            .get("expected_body_digest")
            .and_then(Value::as_str)
            .is_none()
    {
        return Err(Error::engine(
            "body missing fixed values or explicit record port",
        ));
    }
    // No mutable binding read before replay; kernel re-resolves the pinned
    // entry, SAME static row and new-write binding on its own transaction.
    Ok(super::lifecycle::ArtifactBodySavePlan {
        invocation: invocation.clone(),
        source_event_id: source_event_id.into(),
    })
}

async fn invoke_body_set(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
) -> Result<Value> {
    let plan = compose_body_plan(db, caller, invocation, entry, manifest, source_event_id).await?;
    match super::lifecycle::save_body_from_artifact(db, caller, plan).await? {
        super::lifecycle::ArtifactBodyOutcome::Committed { receipt } => {
            Ok(without_null_refresh(encode(*receipt)))
        }
        super::lifecycle::ArtifactBodyOutcome::Refused { code, message } => {
            Ok(rejected(invocation, &code, message))
        }
    }
}

/// Private canonical title dispatch, task `da148be`. Composes the plan,
/// runs it through the governed rename kernel, and maps the typed outcome
/// to intent results with the `{record_id, key:"name", before, after,
/// version}` receipt. Wired on the public native.html.v1 path only; MDX
/// title invocation remains `title_unavailable`.
async fn invoke_title_set(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
) -> Result<Value> {
    let plan =
        match compose_title_plan(db, caller, invocation, entry, manifest, source_event_id).await? {
            Ok(plan) => plan,
            Err((code, message)) => return Ok(rejected(invocation, &code, message)),
        };
    // The wrapper builds its own fixed arguments from the plan: no frame
    // fields or origin cross this boundary.
    match super::lifecycle::rename_record_from_artifact(db.clone(), caller.clone(), plan).await? {
        super::lifecycle::ArtifactTitleOutcome::Committed { receipt } => {
            let changes = vec![IntentChange {
                record_id: receipt
                    .get("record_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                key: "name".to_string(),
                before: receipt.get("before").cloned(),
                after: receipt.get("after").cloned(),
                version: receipt
                    .get("version")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            }];
            Ok(without_null_refresh(encode(
                ArtifactIntentResult::committed(&invocation.idempotency_key, changes),
            )))
        }
        super::lifecycle::ArtifactTitleOutcome::Refused { code, message } => {
            Ok(rejected(invocation, &code, message))
        }
        super::lifecycle::ArtifactTitleOutcome::Conflict {
            current_version,
            conflicting_event_id,
        } => Ok(without_null_refresh(encode(
            ArtifactIntentResult::Conflict {
                version: native_artifact_runtime::artifact_intents::INTENT_RESULT_VERSION.into(),
                idempotency_key: invocation.idempotency_key.clone(),
                error: IntentError::retryable(
                    "title_conflict",
                    "the record moved since it was read; re-read the record and retry",
                ),
                current_version,
                conflicting_event_id,
                competing_actor: None,
                refresh: None,
            },
        ))),
    }
}

/// Compose the fixed title plan from the parsed entry and the invocation.
/// Exactly the declared record slot and the fixed `title` value: missing
/// fillings cannot rename, and extra fillings cannot smuggle scope. The
/// title travels verbatim; blank titles refuse in the kernel with the
/// comment.create nonblank rule. The observed `rec:` token travels
/// untouched for the in-transaction CAS; no frame CAS is accepted.
async fn compose_title_plan(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
    entry: &mdx_v2::InteractionEntry,
    manifest: &mdx_v2::ArtifactManifest,
    source_event_id: &str,
) -> Result<std::result::Result<super::lifecycle::ArtifactTitlePlan, (String, String)>> {
    let reject = |code: &str, message: String| (code.to_string(), message);
    let Some(guard) = &invocation.alpha_install_guard else {
        return Ok(Err(reject(
            "alpha_guard_required",
            "title.set requires a personal-install guard; unguarded renames are not admitted"
                .to_string(),
        )));
    };
    if guard.artifact_id != invocation.artifact_id {
        return Ok(Err(reject(
            "alpha_guard_artifact_mismatch",
            "the install guard names a different artifact than the invocation".to_string(),
        )));
    }
    if source_event_id != guard.source_revision {
        return Ok(Err(reject(
            "alpha_guard_source_mismatch",
            "the title plan source must be the guard's pinned source revision".to_string(),
        )));
    }
    if entry.title.is_none() {
        return Ok(Err(reject(
            "invalid_declaration",
            format!("title.set entry '{}' declares no title envelope", entry.id),
        )));
    }
    if entry.slots.len() != 1 {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "title.set entry '{}' declares no single record slot",
                entry.id
            ),
        )));
    }
    let (record_slot, record_decl) = entry.slots.iter().next().expect("checked");
    let Some(record_id) = invocation.slots.get(record_slot).cloned() else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("record slot '{record_slot}' is unfilled"),
        )));
    };
    if record_id.trim().is_empty() {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("record slot '{record_slot}' is blank"),
        )));
    }
    if let Some(extra) = invocation.slots.keys().find(|name| *name != record_slot) {
        return Ok(Err(reject(
            "unknown_slot",
            format!("entry '{}' declares no slot '{extra}'", entry.id),
        )));
    }
    let Some(title) = invocation.values.get("title").and_then(Value::as_str) else {
        return Ok(Err(reject(
            "slot_unfilled",
            format!("entry '{}' needs its title value", entry.id),
        )));
    };
    let title = title.to_string();
    if let Some(extra) = invocation
        .values
        .keys()
        .find(|name| name.as_str() != "title")
    {
        return Ok(Err(reject(
            "unknown_slot",
            format!("entry '{}' declares no value '{extra}'", entry.id),
        )));
    }
    // Candidate binding scope from the entry's explicit port, re-proved on
    // the write transaction before any replay or append. Mirrors the facet
    // pre-transaction derivation; revocation or rebinding fails there.
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
        Err(diagnostic) => {
            return Ok(Err((
                diagnostic
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or("named_input_unbound")
                    .to_string(),
                diagnostic
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("the title record port is not bound")
                    .to_string(),
            )))
        }
    };
    let Some(port) = (match &record_decl.domain {
        SlotDomain::BoundInput { port } => port.clone(),
        SlotDomain::Values { .. } => None,
    }) else {
        return Ok(Err(reject(
            "invalid_declaration",
            format!(
                "title.set entry '{}' declares no explicit record port",
                entry.id
            ),
        )));
    };
    let Some(bound) = ports
        .iter()
        .find(|bound| bound.port == port && bound.writable_records && bound.root_readable)
    else {
        return Ok(Err(reject(
            "named_input_unbound",
            format!("record input port '{port}' is not bound to a readable Collection"),
        )));
    };
    let observed_token = invocation
        .observed
        .get(&record_id)
        .and_then(|keys| keys.get(super::lifecycle::TITLE_OBSERVED_KEY))
        .cloned();
    Ok(Ok(super::lifecycle::ArtifactTitlePlan {
        artifact_id: invocation.artifact_id.clone(),
        entry_id: entry.id.clone(),
        entry: entry.clone(),
        source_event_id: source_event_id.to_owned(),
        source_digest: invocation.source_digest.clone(),
        record_id,
        title,
        observed_token,
        scope_port: bound.port.clone(),
        scope_collection_id: bound.collection_id.clone(),
        scope_kind: bound.kind.clone(),
        idempotency_key: invocation.idempotency_key.clone(),
        gesture: invocation.gesture.clone(),
        guard: guard.clone(),
        // Admission metadata is resolved fresh by the title kernel at its
        // install guard stage (D7 §4C.2 N3c); composition carries none.
        resolved_admission: None,
    }))
}

#[inline(never)]
fn interaction_future<F: std::future::Future>(make: impl FnOnce() -> F) -> std::pin::Pin<Box<F>> {
    Box::pin(make())
}

async fn invoke_artifact_interaction(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let invocation: ArtifactInvocation = parse_args(TOOL, arguments)?;
    // Shape stays first but is held, not answered through Legacy blindly: an
    // unreadable artifact propagates the ordinary View failure (no Ok wrapper
    // lookup), and a visible one is classified from its actual cited source
    // before the typed `invalid_invocation` returns. No input normalization,
    // no replay consult, no command execution on that path.
    let shape_error = invocation
        .validate_shape()
        .err()
        .map(|message| message.to_string());
    let invocation_digest = invocation_digest(&invocation)?;
    // The artifact must be one this caller may see before anything about it —
    // including whether its digest is stale — is reported back.
    interaction_future(|| {
        require_record(
            &db,
            &caller,
            TOOL,
            &invocation.artifact_id,
            Capability::View,
        )
    })
    .await?;
    // Classify the cited entry from its actual immutable source BEFORE the
    // legacy creation replay, so a comment entry can never inherit an old
    // generic `record.create` receipt or conflict. Only a verified
    // non-comment citation runs the unchanged legacy replay; an unresolved
    // citation skips it and continues to ordinary current resolution, whose
    // outcome is identical to an absent candidate.
    //
    // Reversal mode (D7 slice U2b) dispatches before all of that: when
    // `reverses` is present the tool reverses the named original invocation
    // instead of running validation steps 1–5. The original entry may no
    // longer be in the current manifest — editing the artifact must not
    // strand an undo — so there is no cited-entry classification, no replay
    // consult and no manifest resolution on this path. Shape refusals,
    // including every reverses rule, answer `invalid_invocation`.
    if invocation.reverses.is_some() {
        if let Some(message) = shape_error {
            return Ok(encode(ArtifactIntentResult::invalid(
                correlation(&invocation),
                IntentError::new("invalid_invocation", message),
            )));
        }
        let result = interaction_future(|| {
            super::artifact_reversal::revert_invocation_in(&db, &caller, &invocation)
        })
        .await?;
        return Ok(encode(result));
    }
    // Effect-gesture check (D7 §4B, G2): verified before any replay consult or
    // write, so an invalid token refuses with zero writes. The reversal path
    // above verifies inside `revert_invocation_in`, where the record resolves.
    let gesture_evidence = match check_effect_gesture(&caller, &invocation) {
        GestureCheck::Absent => None,
        GestureCheck::Evidence(evidence) => Some(evidence),
        GestureCheck::Refused { code, message } => {
            return Ok(rejected(&invocation, code, message));
        }
    };
    let cited_class =
        interaction_future(|| classify_cited_entry(&db, &caller, &invocation)).await?;
    if let Some(message) = shape_error {
        // Pre-admission shape refusal with server-derived disposition: actual
        // Comment already marked at classification, Unresolved marks here,
        // verified Other stays Legacy (existing wrapper behavior unchanged).
        if cited_class != CitedEntryClass::Other {
            crate::mcp::registry::note_invoke_domain_owned();
        }
        return Ok(encode(ArtifactIntentResult::invalid(
            correlation(&invocation),
            IntentError::new("invalid_invocation", message),
        )));
    }
    if cited_class == CitedEntryClass::Other {
        if let Some(replayed) =
            interaction_future(|| replayed_creation(&db, &caller, &invocation, &invocation_digest))
                .await?
        {
            return Ok(interaction_future(|| {
                maybe_include_next_plan(&db, &caller, &invocation, replayed)
            })
            .await);
        }
    }
    let read_lens = lens::ReadLens::live(&db);
    let resolved = match interaction_future(|| {
        resolve_artifact(
            &read_lens,
            &caller,
            &invocation.artifact_id,
            V2SnapshotMode::InspectOnly,
            false,
        )
    })
    .await?
    {
        Ok(resolved) => resolved,
        Err(diagnostic) => {
            // Unresolved ordinary pre-verification refusal: mark DomainOwned.
            // Comment already marked at classification; Other preserves Legacy.
            if cited_class == CitedEntryClass::Unresolved {
                crate::mcp::registry::note_invoke_domain_owned();
            }
            return Ok(from_diagnostic(&invocation, &diagnostic));
        }
    };
    if !matches!(
        resolved.runtime_id.as_str(),
        mdx_v2::RUNTIME_ID | crate::artifact_html::RUNTIME_ID
    ) {
        if cited_class == CitedEntryClass::Unresolved {
            crate::mcp::registry::note_invoke_domain_owned();
        }
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
                if cited_class == CitedEntryClass::Unresolved {
                    crate::mcp::registry::note_invoke_domain_owned();
                }
                return Ok(rejected(
                    &invocation,
                    "invalid_artifact_body",
                    failure.message,
                ));
            }
        }
    } else {
        let parsed = match interaction_future(|| {
            tokio::task::spawn_blocking(move || mdx_v2::parse_artifact_cached(&body, &partition))
        })
        .await
        .map_err(|_| Error::engine(format!("{TOOL}: artifact compiler worker terminated")))?
        {
            Ok((parsed, _cache_state)) => parsed,
            Err(failure) => {
                if cited_class == CitedEntryClass::Unresolved {
                    crate::mcp::registry::note_invoke_domain_owned();
                }
                return Ok(rejected(
                    &invocation,
                    "invalid_artifact_body",
                    failure.message,
                ));
            }
        };
        let mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("an artifact source yields an artifact manifest");
        };
        (parsed.source_sha256, manifest)
    };

    // 1. A stale artifact cannot invoke against an edited manifest.
    if source_sha256 != invocation.source_digest {
        if cited_class == CitedEntryClass::Unresolved {
            crate::mcp::registry::note_invoke_domain_owned();
        }
        return Ok(rejected(
            &invocation,
            "stale_source_digest",
            "the artifact body has changed since this artifact was rendered; re-render and retry",
        ));
    }
    // 2. The entry must be declared in THAT manifest.
    let Some(entry) = manifest.interaction(&invocation.entry_id) else {
        if cited_class == CitedEntryClass::Unresolved {
            crate::mcp::registry::note_invoke_domain_owned();
        }
        return Ok(rejected(
            &invocation,
            "unknown_entry",
            format!(
                "artifact declares no interaction entry '{}'",
                invocation.entry_id
            ),
        ));
    };
    if entry.effect == InteractionEffect::BodySet {
        crate::mcp::registry::note_invoke_domain_owned();
        if resolved.runtime_id != crate::artifact_html::RUNTIME_ID {
            return Ok(rejected(
                &invocation,
                "body_unavailable",
                "body.set runs on native.html.v1 only",
            ));
        }
        // The ordinary Body kernel owns install/source pins, current access,
        // binding/needs membership, digest CAS, bounded encoding and replay.
        return interaction_future(|| {
            invoke_body_set(
                &db,
                &caller,
                &invocation,
                entry,
                &manifest,
                &source_event_id,
            )
        })
        .await;
    }
    if entry.effect == InteractionEffect::CommentCreate {
        // Late actual Comment is always DomainOwned. Positive cited Comment
        // already marked at classification; Unresolved late Comment marks here.
        // This closes the pool-snapshot vs ReadLens race without moving gates.
        crate::mcp::registry::note_invoke_domain_owned();
        if resolved.runtime_id != crate::artifact_html::RUNTIME_ID {
            // MDX comment invocation remains unsupported: refuse after
            // parsed-entry resolution so a comment entry can never fall
            // through to facet logic or mint facet preconditions.
            return Ok(rejected(
                &invocation,
                "comment_unavailable",
                "comment.create entries are not executable on this runtime; the governed comment transaction runs on native.html.v1 only",
            ));
        }
        // Public native.html.v1 path only: guard/submit via the existing
        // composer/kernel. MDX stays above; generic specialized refusals and
        // ordinary/facet/triage/Tasks paths below stay unchanged.
        return interaction_future(|| {
            invoke_comment_create(
                &db,
                &caller,
                &invocation,
                entry,
                &manifest,
                &source_event_id,
                gesture_evidence,
            )
        })
        .await;
    }
    if entry.effect == InteractionEffect::MessageReact {
        // Late actual React is always DomainOwned, like Comment above.
        crate::mcp::registry::note_invoke_domain_owned();
        if resolved.runtime_id != crate::artifact_html::RUNTIME_ID {
            // MDX react invocation remains unsupported: refuse after
            // parsed-entry resolution so a react entry can never fall
            // through to facet logic or mint facet preconditions.
            return Ok(rejected(
                &invocation,
                "react_unavailable",
                "message.react entries are not executable on this runtime; the governed reaction transaction runs on native.html.v1 only",
            ));
        }
        // Public native.html.v1 path only: guard/submit via the governed
        // reaction kernel. Ordinary/facet/triage/Tasks paths below stay
        // unchanged, and acknowledgement state is never touched.
        return interaction_future(|| {
            invoke_message_react(
                &db,
                &caller,
                &invocation,
                entry,
                &manifest,
                &source_event_id,
                gesture_evidence,
            )
        })
        .await;
    }
    if entry.effect == InteractionEffect::TitleSet {
        // Late actual Title is always DomainOwned, like Comment above.
        crate::mcp::registry::note_invoke_domain_owned();
        if resolved.runtime_id != crate::artifact_html::RUNTIME_ID {
            // MDX title invocation remains unsupported: refuse after
            // parsed-entry resolution so a title entry can never fall
            // through to facet logic or mint facet preconditions.
            return Ok(rejected(
                &invocation,
                "title_unavailable",
                "title.set entries are not executable on this runtime; the governed rename transaction runs on native.html.v1 only",
            ));
        }
        // Public native.html.v1 path only: guard/submit via the governed
        // rename kernel. Ordinary/facet/triage/Tasks paths below stay
        // unchanged.
        return interaction_future(|| {
            invoke_title_set(
                &db,
                &caller,
                &invocation,
                entry,
                &manifest,
                &source_event_id,
            )
        })
        .await;
    }
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
        ) || super::tab_effect_catalogue::match_arm(entry).is_none()
        {
            return Ok(rejected(
                &invocation,
                "alpha_guard_facet_unconsented",
                format!(
                    "the personal-install guard consents only to facet '{}' or the tasks lifecycle arm; entry '{}' targets '{}'",
                    super::alpha_tabs::ALPHA_GUARD_FACET,
                    entry.id,
                    entry.facet,
                ),
            ));
        }
    }
    if entry.effect == InteractionEffect::RecordCreate {
        // A citation classified as a comment, react or title must never
        // reach the generic creation kernel, including its own
        // in-transaction legacy replay. Source-SHA equality makes a
        // positive comment/react/title citation and a `record.create`
        // current entry mutually exclusive, so this is an explicit
        // fail-closed bypass rather than a reachable reclassification.
        if cited_class == CitedEntryClass::Comment
            || cited_class == CitedEntryClass::React
            || cited_class == CitedEntryClass::Title
            || cited_class == CitedEntryClass::Body
        {
            // Unreachable per the comment above (a react/title citation
            // never resolves a `record.create` entry); the code names the
            // cited family so a future reachable path cannot misreport it.
            let (code, message) = if cited_class == CitedEntryClass::React {
                (
                    "react_unavailable",
                    "message.react entries never reach the generic creation kernel",
                )
            } else if cited_class == CitedEntryClass::Body {
                (
                    "body_unavailable",
                    "body.set entries never reach the generic creation kernel",
                )
            } else if cited_class == CitedEntryClass::Title {
                (
                    "title_unavailable",
                    "title.set entries never reach the generic creation kernel",
                )
            } else {
                (
                    "comment_unavailable",
                    "comment.create entries are declared but not yet executable; the governed comment transaction is a later increment",
                )
            };
            return Ok(rejected(&invocation, code, message));
        }
        let created = interaction_future(|| {
            invoke_record_create(
                &db,
                &caller,
                &invocation,
                entry,
                &manifest,
                &source_event_id,
                &invocation_digest,
                gesture_evidence,
            )
        })
        .await?;
        return Ok(interaction_future(|| {
            maybe_include_next_plan(&db, &caller, &invocation, created)
        })
        .await);
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
    let ports = match interaction_future(|| {
        resolve_bound_input_ports(
            &read_lens,
            &caller,
            &invocation.artifact_id,
            &manifest,
            &source_event_id,
            &source_sha256,
        )
    })
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
    if !interaction_future(|| can_record(&db, &caller, &record_id, Capability::Edit)).await? {
        return Ok(rejected(
            &invocation,
            "permission_denied",
            format!("the authenticated principal may not edit record {record_id}"),
        ));
    }
    let mut in_binding = BTreeSet::new();
    for bound in &scope {
        match interaction_future(|| {
            resolve_bound_input_records(&read_lens, &caller, &invocation.artifact_id, bound)
        })
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
        InteractionEffect::CommentCreate => {
            unreachable!("comment.create dispatches before the facet write path")
        }
        InteractionEffect::MessageReact => {
            unreachable!("message.react dispatches before the facet write path")
        }
        InteractionEffect::TitleSet => {
            unreachable!("title.set dispatches before the facet write path")
        }
        InteractionEffect::BodySet => {
            return Ok(rejected(
                &invocation,
                "body_unavailable",
                "body.set entries never reach the facet write path",
            ));
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
    // Pre-transaction admitted scope, threaded for the facet-set arm's
    // in-transaction currency proof. Legacy arms ignore it.
    let scope_pairs: Vec<(String, String, String)> = scope
        .iter()
        .map(|bound| {
            (
                bound.port.clone(),
                bound.collection_id.clone(),
                bound.kind.clone(),
            )
        })
        .collect();
    let committed = interaction_future(|| {
        commit_declared_write(
            &db,
            &caller,
            entry,
            write,
            &invocation,
            &scope_pairs,
            &source_event_id,
            &source_sha256,
            gesture_evidence,
        )
    })
    .await?;
    let mut encoded = encode(committed.0);
    if let Some(act) = committed.1 {
        encoded["act"] = act.into();
    }
    Ok(interaction_future(|| maybe_include_next_plan(&db, &caller, &invocation, encoded)).await)
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
#[allow(clippy::too_many_arguments)] // Keep manifest and source pins explicit at the write boundary.
async fn commit_declared_write(
    db: &Db,
    caller: &Caller,
    entry: &mdx_v2::InteractionEntry,
    mut write: DeclaredWrite,
    invocation: &ArtifactInvocation,
    scope: &[(String, String, String)],
    source_event_id: &str,
    source_sha256: &str,
    gesture_evidence: Option<Value>,
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
            time_type: None,
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
    //
    // Resolve package and static admission together from the fresh row.
    // The result is local to this transaction; no caller metadata bypasses
    // current pins/consent. Dynamic facet gates consume it only after replay.
    let resolved_admission: Option<super::alpha_tabs::ResolvedAlphaAdmission> =
        if let Some(guard) = &invocation.alpha_install_guard {
            let claim = super::effect_admission::PackageClaim::alpha(guard);
            match super::alpha_tabs::resolve_alpha_admission_in(
                &mut tx,
                caller,
                claim,
                &invocation.artifact_id,
                &invocation.source_digest,
                entry,
                super::alpha_tabs::GuardScope::Facet,
            )
            .await?
            {
                Ok(resolved) => Some(resolved),
                Err(refusal) => {
                    let (code, message) = super::effect_admission::render_refusal(
                        super::effect_admission::AdmissionSource::AlphaTabInstall,
                        &refusal,
                    );
                    return refuse(&code, message);
                }
            }
        } else {
            None
        };

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
            AND json_extract(payload,'$.origin.reverses') IS NULL
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
    // Facet-set post-replay dynamic gates: static consent passed in the
    // guard above and permission before the replay branch, so a replay
    // keeps every static gate while skipping these mutable ones. A replay
    // commits nothing, so a target that has since left the declared NEED
    // still settles its prior receipt; binding removal is still refused by
    // the pre-transaction gate exactly as for the older arms (no legacy
    // widening). A fresh commit proves current need membership and binding
    // on this snapshot before CAS.
    if super::tab_effect_catalogue::match_arm(entry)
        == Some(super::tab_effect_catalogue::TabEffectArm::FacetSet)
    {
        // Record operand derived exactly like the pre-transaction slot
        // check; absent only if that validation moved, failing closed.
        let gated_record_id: Option<String> = entry
            .slots
            .iter()
            .find(|(_, declaration)| declaration.domain.is_record())
            .and_then(|(name, _)| invocation.slots.get(name).cloned());
        // Consume the bound/need admitted before replay, without parsing
        // consent again; binding and membership remain mutable gates here.
        if let Some(resolved) = &resolved_admission {
            if let Some((code, message)) =
                super::alpha_tabs::check_facet_set_post_replay_with_admission_in(
                    &mut tx,
                    caller,
                    resolved,
                    source_event_id,
                    source_sha256,
                    gated_record_id.as_deref(),
                    scope,
                )
                .await?
            {
                return refuse(&code, message);
            }
        }
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

    // Guarded Tasks click slice: the transition source is fixed for any
    // install that explicitly consents to this arm. Unguarded artifacts
    // retain general declared lifecycle interaction semantics. This runs
    // after the replay early-return and after compare-and-set, so a
    // replayed key still settles identically and a stale token still
    // conflicts instead of misreporting state. The guard admits only a
    // declared literal `in_progress` value; this fixes the source state
    // on the same snapshot as the append — anything but `open` refuses
    // here with the state named.
    //
    // N3c: driven by the fresh paired package/admission result,
    // not by the raw guard presence. The resolver above returns early on
    // refusal, so `is_some()` here is equivalent to the previous guard
    // check, with identical bytes/order; it simply threads the neutral
    // admission metadata instead of re-examining the wire.
    if resolved_admission.is_some()
        && matches!(
            super::tab_effect_catalogue::match_arm(entry),
            Some(super::tab_effect_catalogue::TabEffectArm::TasksLifecycle)
        )
    {
        let state: Option<String> =
            sqlx::query_scalar("SELECT lifecycle FROM records WHERE id=? AND deleted_at IS NULL")
                .bind(&write.record_id)
                .fetch_optional(&mut *tx)
                .await?;
        match state.as_deref() {
            Some(super::alpha_tabs::TASKS_LIFECYCLE_SOURCE) => {}
            Some(current) => {
                return refuse(
                    "lifecycle_unexpected_state",
                    format!(
                        "record {} is '{current}', not '{}'; the tasks click moves only {} → {}",
                        write.record_id,
                        super::alpha_tabs::TASKS_LIFECYCLE_SOURCE,
                        super::alpha_tabs::TASKS_LIFECYCLE_SOURCE,
                        super::alpha_tabs::TASKS_LIFECYCLE_TARGET,
                    ),
                )
            }
            None => {
                return refuse(
                    "missing_record",
                    format!("record {} does not exist", write.record_id),
                )
            }
        }
    }

    // 8. Commit, attributed to the actor and to the originating artifact.
    // The optional guard authorization context rides along so a replay under a
    // different context conflicts instead of replaying the earlier commit
    // (see the replay branch above). Absent it serializes as an explicit null;
    // a legacy row that predates the field (key missing) reads back as null
    // too, so ordinary unguarded replay is preserved.
    let mut origin = json!({
        "artifact_id": invocation.artifact_id,
        "entry_id": entry.id,
        "source_digest": invocation.source_digest,
        "idempotency_key": invocation.idempotency_key,
        "gesture": invocation.gesture,
        "alpha_install_guard": serde_json::to_value(&invocation.alpha_install_guard)
            .unwrap_or(Value::Null),
    });
    if let Some(evidence) = gesture_evidence {
        origin["gesture_evidence"] = evidence;
    }
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
    // A declared typed time value (task fef3469) was normalised by the
    // governance call above, and `facet_set_spec` wrote that form with its
    // `time_kind`; the receipt reports what was stored, not what was sent.
    let after = match governed.first() {
        Some(facet) if spine.is_none() && facet.time_type.is_some() => Some(facet.value.clone()),
        _ => write.value.clone(),
    };
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
pub(super) async fn conflicting_event_in(
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
pub(super) async fn current_facet_version(
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

pub(super) async fn current_facet_value(
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
         authorization or a confirmation. With reverses the host undoes one committed artifact or app effect \
         the viewer owns.",
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
                    "description": "Compare-and-set preconditions from get_record: record id to facet key to version token.",
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
                    "description": "Opt-in: attach the next render plan under refresh.plan. Omit for the fast receipt."
                },
                "alpha_install_guard": {
                    "type": "object",
                    "description": "Optional alpha-tab install guard for a reversible facet intent, checked inside the write transaction. See module docs.",
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
                },
                "reverses": {
                    "type": "object",
                    "description": "Optional reversal mode: undo the original invocation named here instead of running a declared entry. Fillings must be empty and source_digest must match the original; include_next_plan is ignored. See module docs.",
                    "properties": {
                        "entry_id": { "type": "string" },
                        "idempotency_key": { "type": "string" }
                    },
                    "required": ["entry_id", "idempotency_key"],
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

    async fn body_composition_fixture() -> (Db, ArtifactInvocation, mdx_v2::ArtifactManifest, String)
    {
        let descriptor = json!({"schema":"native.html.artifact.v2",
            "inputs":{"orders":{"envelope":"native.collection-envelope.v1","required":true,"expose_to_root":true}},
            "capability_requests":[{"capability":"input.read","scope":{"port":"orders"}}],
            "interactions":[{"id":"save","label":"Save","effect":"body.set",
                "slots":{"page":{"domain":{"kind":"bound_input","port":"orders"}}},"body":{"max_bytes":32768}}]});
        let source = format!(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Body</title></head><body><main><h1>Body</h1><script type="application/json" id="native-artifact-manifest">{descriptor}</script></main></body></html>"#
        );
        let manifest = crate::artifact_html::validate_cached(&source)
            .unwrap()
            .interaction_manifest();
        let db = crate::create_database(":memory:").await.unwrap();
        let mut tools = crate::mcp::ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut tools).unwrap();
        let artifact = tools.call(db.clone(),Caller::local(),"create_record",
            json!({"type":"Document","kind":"artifact","name":"Body composition","body":source,"facets":{"runtime":"native.html.v1"},"reason":"test"})).await.unwrap();
        let artifact_id = artifact["id"].as_str().unwrap().to_owned();
        let event: String = sqlx::query_scalar(
            "SELECT id FROM content_events WHERE record_id=? AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 1",
        )
        .bind(&artifact_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        let digest = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&source);
        let invocation = ArtifactInvocation {
            version: native_artifact_runtime::artifact_intents::INVOCATION_VERSION.into(),
            artifact_id: artifact_id.clone(),
            entry_id: "save".into(),
            source_digest: digest,
            slots: BTreeMap::from([("page".into(), "target".into())]),
            values: BTreeMap::from([
                ("body".into(), json!(" literal\r\n")),
                ("expected_body_digest".into(), json!("a".repeat(64))),
            ]),
            observed: BTreeMap::new(),
            idempotency_key: "compose:body".into(),
            gesture: Some("click".into()),
            include_next_plan: false,
            reverses: None,
            alpha_install_guard: Some(
                native_artifact_runtime::artifact_intents::AlphaTabInstallGuard {
                    package: "agent.body-compose".into(),
                    expected_install_event_id: "fixture-generation".into(),
                    artifact_id,
                    source_revision: event.clone(),
                    version: "1".into(),
                    digest: format!("sha256:{}", "a".repeat(64)),
                    declaration_digest: "b".repeat(64),
                },
            ),
        };
        (db, invocation, manifest, event)
    }

    #[tokio::test]
    async fn body_composition_preserves_exact_values_without_dynamic_preflight() {
        let (db, invocation, manifest, event) = body_composition_fixture().await;
        let entry = manifest.interaction("save").unwrap();
        let plan = compose_body_plan(&db, &Caller::local(), &invocation, entry, &manifest, &event)
            .await
            .unwrap();
        assert_eq!(plan.invocation, invocation);
        assert_eq!(plan.source_event_id, event);
        let bindings: i64 = sqlx::query_scalar("SELECT count(*) FROM artifact_inputs")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(bindings, 0); // composition is not mutable binding authority.
    }

    #[tokio::test]
    async fn body_composition_rejects_observed_extras_wrong_source_and_mdx() {
        let (db, invocation, manifest, event) = body_composition_fixture().await;
        let entry = manifest.interaction("save").unwrap();
        for change in 0..5 {
            let mut invalid = invocation.clone();
            match change {
                0 => {
                    invalid.values.insert("title".into(), json!("smuggled"));
                }
                1 => {
                    invalid.observed.insert("target".into(), BTreeMap::new());
                }
                2 => {
                    invalid
                        .alpha_install_guard
                        .as_mut()
                        .unwrap()
                        .source_revision = "wrong".into();
                }
                3 => {
                    invalid.slots.insert("other".into(), "target".into());
                }
                _ => {
                    invalid.values.insert("body".into(), json!(null));
                }
            }
            assert!(
                compose_body_plan(&db, &Caller::local(), &invalid, entry, &manifest, &event)
                    .await
                    .is_err()
            );
        }
        // Actual stored runtime, not a supplied runtime flag.
        sqlx::query(
            "UPDATE facet_values SET value='native.mdx.v2' WHERE record_id=? AND key='runtime'",
        )
        .bind(&invocation.artifact_id)
        .execute(db.write_pool())
        .await
        .unwrap();
        assert!(
            compose_body_plan(&db, &Caller::local(), &invocation, entry, &manifest, &event)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn body_public_html_dispatch_reaches_guarded_kernel_without_facet_fallback() {
        let (db, invocation, _, _) = body_composition_fixture().await;
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let result = invoke_artifact_interaction(
            db.clone(),
            Caller::local(),
            serde_json::to_value(invocation).unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(result["status"], "rejected");
        assert_eq!(result["error"]["code"], "alpha_guard_missing_install");
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap(),
            count
        );
    }

    fn dormant_body_source() -> String {
        r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "orders" } }],
  interactions: [{ id: "save", label: "Save", effect: "body.set",
    slots: { page: { domain: { kind: "bound_input", port: "orders" } } },
    body: { max_bytes: 32768 } }]
}

<Metric label="Total" value={1} />
"#.to_owned()
    }

    #[tokio::test]
    async fn body_citation_is_not_legacy_creation_replay() {
        let db = classifier_db().await;
        let source = dormant_body_source();
        let digest = sha256_hex(source.as_bytes());
        insert_body(&db, CLASSIFIER_ARTIFACT, "body:dormant", &source).await;
        insert_attestation(
            &db,
            CLASSIFIER_ARTIFACT,
            "attestation:dormant",
            "body:dormant",
            &digest,
            json!({"schema":"native.mdx.artifact-source.v1"}),
        )
        .await;
        insert_candidate(
            &db,
            "old:create",
            "save",
            "same-key",
            "body:dormant",
            &digest,
            Some("record.create"),
        )
        .await;
        assert_eq!(
            classify_cited_entry(
                &db,
                &Caller::local(),
                &classifier_invocation("save", &digest, "same-key")
            )
            .await
            .unwrap(),
            CitedEntryClass::Body
        );
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn body_dispatch_refuses_mdx_and_malformed_html_without_write() {
        let _guard = native_artifact_runtime::mdx::test_guard();
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        for (runtime, source) in [
            (mdx_v2::RUNTIME_ID, dormant_body_source()),
            (
                crate::artifact_html::RUNTIME_ID,
                html_source_from_mdx(&dormant_body_source()),
            ),
        ] {
            let id = uuid::Uuid::new_v4().to_string();
            registry.call(db.clone(), Caller::local(), "create_record", json!({
                "id":id,"type":"Document","kind":"artifact","name":"Dormant Body",
                "body":source,"facets":{"runtime":runtime},"reason":"Dormant refusal fixture."
            })).await.unwrap();
            let before: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let mut invocation =
                classifier_invocation("save", &sha256_hex(source.as_bytes()), "body:key");
            invocation.artifact_id = id;
            // MDX stays unavailable; malformed HTML reaches the closed Body
            // composer and never generic slot/observation/facet processing.
            let result = invoke_artifact_interaction(
                db.clone(),
                Caller::local(),
                serde_json::to_value(invocation).unwrap(),
            )
            .await;
            if runtime == mdx_v2::RUNTIME_ID {
                let result = result.unwrap();
                assert_eq!(result["status"], "rejected");
                assert_eq!(result["error"]["code"], "body_unavailable");
            } else {
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("body alpha guard required"));
            }
            let after: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            assert_eq!(before, after, "No receipt, facet, lifecycle or body event");
        }
    }

    #[test]
    fn classify_effect_routes_react_to_the_react_class() {
        assert_eq!(
            classify_effect(InteractionEffect::MessageReact),
            CitedEntryClass::React
        );
        assert_eq!(
            classify_effect(InteractionEffect::CommentCreate),
            CitedEntryClass::Comment
        );
        assert_eq!(
            classify_effect(InteractionEffect::FacetSet),
            CitedEntryClass::Other
        );
    }

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

    /// Comment tokens are deterministic seals over explicit scope plus live
    /// parent state: every scope input, the process key, and every snapshot
    /// field diverges the token, and the token leaks none of them.
    #[test]
    fn comment_tokens_diverge_by_scope_secret_and_parent_state() {
        use native_artifact_runtime::artifact_intents::parse_comment_token;
        let key_a = [7u8; 32];
        let key_b = [9u8; 32];
        let state = CommentParentState {
            revision_seq: 41,
            revision_event_id: "0196c2d4-0000-4000-8000-000000000001".into(),
            record_type: "Document".into(),
            kind: Some("note".into()),
            lifecycle: None,
            home_id: Some("home".into()),
            part_of: vec!["bearer".into()],
        };
        let context = CommentMintContext {
            caller_credential: "acct:fixture-viewer",
            artifact_id: "artifact",
            source_event_id: "source-event",
            source_digest: "sourcedigest",
        };
        let token = seal_comment_token_with_key(&key_a, &context, "target", &state);
        assert!(token.starts_with("ct:"), "{token}");
        assert_eq!(token.len(), 3 + 32, "{token}");
        let bytes = parse_comment_token(&token).expect("minted token parses");
        assert!(verify_comment_token(&token, &bytes));
        let mut flipped = bytes;
        flipped[0] ^= 1;
        assert!(!verify_comment_token(&token, &flipped));
        assert!(!verify_comment_token(
            "ct:00000000000000000000000000000000",
            &bytes
        ));
        // Opaque: non-hex scope text cannot occur in the token.
        for secret in [
            "acct:fixture-viewer",
            "target",
            "0196c2d4-0000-4000-8000-000000000001",
        ] {
            assert!(!token.contains(secret), "{token} leaks {secret}");
        }
        // Scope divergence, one field at a time.
        let scope_case = |field: &str, context: CommentMintContext<'_>| {
            let other = seal_comment_token_with_key(&key_a, &context, "target", &state);
            assert_ne!(token, other, "scope field {field} must diverge the token");
        };
        scope_case(
            "caller",
            CommentMintContext {
                caller_credential: "acct:other-viewer",
                ..context_clone(&context)
            },
        );
        scope_case(
            "artifact",
            CommentMintContext {
                artifact_id: "other-artifact",
                ..context_clone(&context)
            },
        );
        scope_case(
            "source event",
            CommentMintContext {
                source_event_id: "other-source-event",
                ..context_clone(&context)
            },
        );
        scope_case(
            "source digest",
            CommentMintContext {
                source_digest: "otherdigest",
                ..context_clone(&context)
            },
        );
        let retargeted = seal_comment_token_with_key(&key_a, &context, "other-target", &state);
        assert_ne!(token, retargeted, "target must diverge the token");
        // Secret divergence.
        assert_ne!(
            token,
            seal_comment_token_with_key(&key_b, &context, "target", &state),
            "process key must diverge the token"
        );
        // Parent-state divergence, one field at a time.
        let state_case = |field: &str, state: CommentParentState| {
            let other = seal_comment_token_with_key(&key_a, &context, "target", &state);
            assert_ne!(token, other, "parent field {field} must diverge the token");
        };
        state_case(
            "revision",
            CommentParentState {
                revision_seq: 42,
                ..state.clone()
            },
        );
        state_case(
            "revision event",
            CommentParentState {
                revision_event_id: "0196c2d4-0000-4000-8000-000000000002".into(),
                ..state.clone()
            },
        );
        state_case(
            "type",
            CommentParentState {
                record_type: "WorkItem".into(),
                ..state.clone()
            },
        );
        state_case(
            "kind",
            CommentParentState {
                kind: None,
                ..state.clone()
            },
        );
        state_case(
            "lifecycle",
            CommentParentState {
                lifecycle: Some("open".into()),
                ..state.clone()
            },
        );
        state_case(
            "home",
            CommentParentState {
                home_id: None,
                ..state.clone()
            },
        );
        state_case(
            "part_of",
            CommentParentState {
                part_of: vec![],
                ..state.clone()
            },
        );
    }

    /// Test-only clone for a context of borrowed scope strings.
    fn context_clone<'a>(context: &CommentMintContext<'a>) -> CommentMintContext<'a> {
        CommentMintContext {
            caller_credential: context.caller_credential,
            artifact_id: context.artifact_id,
            source_event_id: context.source_event_id,
            source_digest: context.source_digest,
        }
    }

    /// Parent state comes from the live transaction: sibling appends leave
    /// the parent's revision (and token) stable, while an edit to the
    /// parent moves both. Unknown parents fail closed with no fabricated
    /// revision.
    #[tokio::test]
    async fn comment_parent_state_tracks_edits_but_not_sibling_appends() {
        let db = crate::create_database(":memory:").await.unwrap();
        let mut registry = ToolRegistry::new();
        crate::mcp::tools::register_surface_tools(&mut registry).unwrap();
        let created = registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note", "name": "Thread",
                    "body": "hello", "reason": "comment token fixture.",
                }),
            )
            .await
            .unwrap();
        let parent = created["id"].as_str().unwrap().to_owned();
        let key = [7u8; 32];
        let context = CommentMintContext {
            caller_credential: "acct:fixture-viewer",
            artifact_id: "artifact",
            source_event_id: "source-event",
            source_digest: "sourcedigest",
        };
        let read = |db: crate::Db, parent: String| async move {
            let mut tx = db.pool().begin().await.unwrap();
            read_comment_parent_state_in(&mut tx, &parent).await
        };
        let before = read(db.clone(), parent.clone())
            .await
            .unwrap()
            .expect("live parent has state");
        let token_before = seal_comment_token_with_key(&key, &context, &parent, &before);
        // A sibling append touches only its own record: the parent's state
        // and token are byte-identical.
        registry
            .call(
                db.clone(),
                Caller::local(),
                "create_record",
                json!({
                    "type": "Document", "kind": "note", "name": "Sibling",
                    "body": "unrelated", "reason": "comment token fixture.",
                }),
            )
            .await
            .unwrap();
        let stable = read(db.clone(), parent.clone())
            .await
            .unwrap()
            .expect("parent still has state");
        assert_eq!(before, stable);
        assert_eq!(
            token_before,
            seal_comment_token_with_key(&key, &context, &parent, &stable)
        );
        // An edit to the parent moves the revision and the token.
        registry
            .call(
                db.clone(),
                Caller::local(),
                "update_record",
                json!({
                    "id": parent, "body_append": " more",
                    "reason": "comment token fixture.",
                }),
            )
            .await
            .unwrap();
        let moved = read(db.clone(), parent.clone())
            .await
            .unwrap()
            .expect("edited parent has state");
        assert!(moved.revision_seq > before.revision_seq);
        assert_ne!(moved.revision_event_id, before.revision_event_id);
        assert_ne!(
            token_before,
            seal_comment_token_with_key(&key, &context, &parent, &moved)
        );
        // Unknown parents fail closed.
        let mut tx = db.pool().begin().await.unwrap();
        assert!(
            read_comment_parent_state_in(&mut tx, "00000000-0000-4000-8000-000000000000")
                .await
                .unwrap()
                .is_none()
        );
    }

    /// Comment plan composition refuses before any store I/O: missing or
    /// mismatched guard identity, and slot/value exclusivity against the
    /// declared bearer and body inputs. The entry below comes from a
    /// genuinely parsed manifest source, never hand-built JSON.
    #[tokio::test]
    async fn compose_comment_plan_refuses_before_binding() {
        use native_artifact_runtime::artifact_intents::{
            AlphaTabInstallGuard, ArtifactInvocation, INVOCATION_VERSION,
        };
        let source = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { orders: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [{ capability: "input.read", scope: { port: "orders" } }],
  interactions: [{ id: "post", label: "Post", effect: "comment.create",
    slots: { bearer: { domain: { kind: "bound_input", port: "orders" } } },
    comment: { position: "root", body: { input: "text", max_bytes: 100 } } }]
}

<Metric label="Total" value={1} />
"#;
        let parsed = native_artifact_runtime::mdx_v2::parse_artifact(source)
            .expect("comment manifest parses");
        let native_artifact_runtime::mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("artifact source yields an artifact manifest");
        };
        let entry = manifest
            .interaction("post")
            .expect("entry resolves")
            .clone();
        let db = crate::create_database(":memory:").await.unwrap();
        let caller = crate::mcp::Caller::local();
        let guard = AlphaTabInstallGuard {
            package: "agent.comment-dispatch".into(),
            expected_install_event_id: "event".into(),
            artifact_id: "artifact".into(),
            source_revision: "revision".into(),
            version: "0.1.0".into(),
            digest: format!("sha256:{}", "b".repeat(64)),
            declaration_digest: "c".repeat(64),
        };
        let invocation = |slots: BTreeMap<String, String>,
                          values: BTreeMap<String, Value>,
                          guard: Option<AlphaTabInstallGuard>| {
            ArtifactInvocation {
                version: INVOCATION_VERSION.into(),
                artifact_id: "artifact".into(),
                entry_id: "post".into(),
                source_digest: "a".repeat(64),
                slots,
                values,
                observed: BTreeMap::new(),
                idempotency_key: "k".into(),
                gesture: Some("click".into()),
                include_next_plan: false,
                alpha_install_guard: guard,
                reverses: None,
            }
        };
        let filled = || {
            (
                BTreeMap::from([("bearer".to_owned(), "record".to_owned())]),
                BTreeMap::from([("text".to_owned(), Value::String("hi".into()))]),
            )
        };
        // Missing guard: comments are consent-gated, no unguarded path.
        let (slots, values) = filled();
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(slots, values, None),
            &entry,
            &manifest,
            "revision",
        )
        .await
        .unwrap()
        .expect_err("unguarded composition must refuse");
        assert_eq!(code, "alpha_guard_required");
        // Guard artifact mismatch.
        let (slots, values) = filled();
        let mut other_guard = guard.clone();
        other_guard.artifact_id = "other".into();
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(slots, values, Some(other_guard)),
            &entry,
            &manifest,
            "revision",
        )
        .await
        .unwrap()
        .expect_err("artifact mismatch must refuse");
        assert_eq!(code, "alpha_guard_artifact_mismatch");
        // Source event must be the guard's pinned revision.
        let (slots, values) = filled();
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(slots, values, Some(guard.clone())),
            &entry,
            &manifest,
            "other-revision",
        )
        .await
        .unwrap()
        .expect_err("source mismatch must refuse");
        assert_eq!(code, "alpha_guard_source_mismatch");
        // Extra slot cannot smuggle scope.
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(
                BTreeMap::from([
                    ("bearer".to_owned(), "record".to_owned()),
                    ("spare".to_owned(), "record".to_owned()),
                ]),
                BTreeMap::from([("text".to_owned(), Value::String("hi".into()))]),
                Some(guard.clone()),
            ),
            &entry,
            &manifest,
            "revision",
        )
        .await
        .unwrap()
        .expect_err("extra slot must refuse");
        assert_eq!(code, "unknown_slot");
        // Missing bearer cannot post.
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(
                BTreeMap::new(),
                BTreeMap::from([("text".to_owned(), Value::String("hi".into()))]),
                Some(guard.clone()),
            ),
            &entry,
            &manifest,
            "revision",
        )
        .await
        .unwrap()
        .expect_err("missing bearer must refuse");
        assert_eq!(code, "slot_unfilled");
        // Missing body cannot post.
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(
                BTreeMap::from([("bearer".to_owned(), "record".to_owned())]),
                BTreeMap::new(),
                Some(guard.clone()),
            ),
            &entry,
            &manifest,
            "revision",
        )
        .await
        .unwrap()
        .expect_err("missing body must refuse");
        assert_eq!(code, "slot_unfilled");
        // Non-string body is outside the declared domain.
        let (code, _) = compose_comment_plan(
            &db,
            &caller,
            &invocation(
                BTreeMap::from([("bearer".to_owned(), "record".to_owned())]),
                BTreeMap::from([("text".to_owned(), json!(3))]),
                Some(guard.clone()),
            ),
            &entry,
            &manifest,
            "revision",
        )
        .await
        .unwrap()
        .expect_err("non-string body must refuse");
        assert_eq!(code, "value_outside_domain");
    }

    // ---- cited-entry classifier (task b9fb9fd family 1) ----

    const CLASSIFIER_ARTIFACT: &str = "artifact:classifier";

    /// A real MDX artifact source with a governed `record.create` entry and,
    /// optionally, a `comment.create` entry. Both are parsed from actual
    /// bytes, never hand-built.
    fn classifier_source(with_comment: bool) -> String {
        let comment = if with_comment {
            r#",
    { id: "post", label: "Post", effect: "comment.create",
      slots: { bearer: { domain: { kind: "bound_input", port: "orders" } } },
      comment: { position: "root", body: { input: "text", max_bytes: 100 } } }"#
        } else {
            ""
        };
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "orders" }} }}],
  interactions: [
    {{ id: "create_note", label: "Note", effect: "record.create",
      create: {{ destination: {{ from: "bound_input", port: "orders" }}, shape: {{
        type: {{ source: {{ from: "literal", value: "Document" }}, domain: {{ kind: "enum", values: ["Document"] }} }},
        kind: {{ source: {{ from: "literal", value: "note" }}, domain: {{ kind: "enum", values: ["note"] }} }},
        fields: {{ name: {{ label: "Title", source: {{ from: "input", input: "note_title" }}, domain: {{ kind: "string", min_length: 1, max_length: 80 }} }} }},
        facets: {{}}
      }} }} }}{comment}
  ]
}}

<Metric label="Total" value={{1}} />
"#
        )
    }

    fn html_source_from_mdx(source: &str) -> String {
        let parsed = native_artifact_runtime::mdx_v2::parse_artifact(source).unwrap();
        let native_artifact_runtime::mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("artifact source yields an artifact manifest")
        };
        let declaration = json!({
            "schema": "native.html.artifact.v2",
            "inputs": manifest.inputs,
            "capability_requests": manifest.capability_requests,
            "interactions": manifest.interactions,
        });
        format!("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Interactions</title><script type=\"application/json\" id=\"native-artifact-manifest\">{declaration}</script></head><body><main><h1>Interactions</h1></main></body></html>")
    }

    /// The digest envelope without `reverses` is byte-identical to the
    /// pre-U2b shape: adding the optional field must not move any existing
    /// idempotency key. With `reverses` present the digest moves.
    #[test]
    fn invocation_digest_ignores_absent_reverses() {
        use sha2::{Digest, Sha256};
        let invocation = classifier_invocation("mark_triaged", &"a".repeat(64), "k");
        assert!(invocation.reverses.is_none());
        let envelope = serde_json::json!({
            "version": invocation.version,
            "artifact_id": invocation.artifact_id,
            "entry_id": invocation.entry_id,
            "source_digest": invocation.source_digest,
            "slots": invocation.slots,
            "values": invocation.values,
            "observed": invocation.observed,
            "gesture": invocation.gesture,
        });
        let expected = hex::encode(Sha256::digest(serde_jcs::to_vec(&envelope).unwrap()));
        assert_eq!(invocation_digest(&invocation).unwrap(), expected);

        let mut reversal = invocation.clone();
        reversal.reverses = Some(
            native_artifact_runtime::artifact_intents::ReversalReference {
                entry_id: "mark_triaged".into(),
                idempotency_key: "k".into(),
            },
        );
        assert_ne!(invocation_digest(&reversal).unwrap(), expected);
    }

    fn classifier_invocation(entry_id: &str, digest: &str, key: &str) -> ArtifactInvocation {
        ArtifactInvocation {
            version: native_artifact_runtime::artifact_intents::INVOCATION_VERSION.into(),
            artifact_id: CLASSIFIER_ARTIFACT.into(),
            entry_id: entry_id.into(),
            source_digest: digest.into(),
            slots: BTreeMap::new(),
            values: BTreeMap::new(),
            observed: BTreeMap::new(),
            idempotency_key: key.into(),
            gesture: None,
            include_next_plan: false,
            alpha_install_guard: None,
            reverses: None,
        }
    }

    async fn classifier_db() -> Db {
        let db = crate::create_database(":memory:").await.unwrap();
        sqlx::query(
            "INSERT INTO records(id,type,kind,name) VALUES (?, 'Document', 'artifact', 'Classifier')",
        )
        .bind(CLASSIFIER_ARTIFACT)
        .execute(db.write_pool())
        .await
        .unwrap();
        db
    }

    async fn insert_body(db: &Db, record_id: &str, event_id: &str, body: &str) {
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status)
             VALUES (?,?,'record.created',?,'local',1,'legacy_unknown')",
        )
        .bind(event_id)
        .bind(record_id)
        .bind(serde_json::to_string(&json!({"body": body})).unwrap())
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn insert_raw_event(db: &Db, record_id: &str, event_id: &str, payload: Option<&str>) {
        sqlx::query(
            "INSERT INTO content_events(id,record_id,type,payload,actor,causal_envelope_version,causal_status)
             VALUES (?,?,'record.created',?,'local',1,'legacy_unknown')",
        )
        .bind(event_id)
        .bind(record_id)
        .bind(payload)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn insert_attestation(
        db: &Db,
        artifact_id: &str,
        attestation_event_id: &str,
        source_event_id: &str,
        source_sha256: &str,
        descriptor: Value,
    ) {
        sqlx::query(
            "INSERT INTO artifact_source_attestations
               (attestation_event_id,artifact_id,source_event_id,source_sha256,descriptor,attestation_sha256,event_seq,created_at)
             VALUES (?,?,?,?,?,?,1,'2026-09-29T00:00:00Z')",
        )
        .bind(attestation_event_id)
        .bind(artifact_id)
        .bind(source_event_id)
        .bind(source_sha256)
        .bind(serde_json::to_string(&descriptor).unwrap())
        .bind("a".repeat(64))
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn insert_candidate(
        db: &Db,
        event_id: &str,
        entry_id: &str,
        key: &str,
        source_event_id: &str,
        source_digest: &str,
        effect: Option<&str>,
    ) {
        let mut origin = json!({
            "kind": "artifact.interaction",
            "artifact_id": CLASSIFIER_ARTIFACT,
            "entry_id": entry_id,
            "source_digest": source_digest,
            "source_event_id": source_event_id,
            "idempotency_key": key,
        });
        if let Some(effect) = effect {
            origin["effect"] = json!(effect);
        }
        let payload = json!({
            "id": format!("{event_id}-record"),
            "home_id": "collection",
            "origin": origin,
        });
        let record_id = format!("{event_id}-record");
        let payload = payload.to_string();
        insert_raw_event(db, &record_id, event_id, Some(&payload)).await;
    }

    #[tokio::test]
    async fn classifier_attested_comment_and_other_follow_the_actual_body() {
        let db = classifier_db().await;
        let source = classifier_source(true);
        let digest = sha256_hex(source.as_bytes());
        insert_body(&db, CLASSIFIER_ARTIFACT, "body:attested", &source).await;
        insert_attestation(
            &db,
            CLASSIFIER_ARTIFACT,
            "attestation:one",
            "body:attested",
            &digest,
            json!({"schema": "native.mdx.artifact-source.v1"}),
        )
        .await;
        let caller = crate::mcp::Caller::local();
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("post", &digest, "attested:comment")
            )
            .await
            .unwrap(),
            CitedEntryClass::Comment
        );
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("create_note", &digest, "attested:other")
            )
            .await
            .unwrap(),
            CitedEntryClass::Other
        );
    }

    #[tokio::test]
    async fn classifier_current_body_requires_the_exact_requested_digest() {
        let db = classifier_db().await;
        let source = classifier_source(true);
        let digest = sha256_hex(source.as_bytes());
        insert_body(&db, CLASSIFIER_ARTIFACT, "body:current", &source).await;
        let caller = crate::mcp::Caller::local();
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("post", &digest, "current:comment")
            )
            .await
            .unwrap(),
            CitedEntryClass::Comment
        );
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("create_note", &digest, "current:other")
            )
            .await
            .unwrap(),
            CitedEntryClass::Other
        );
        // A requested digest the current body does not hash to proves nothing.
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("post", &"0".repeat(64), "current:stale")
            )
            .await
            .unwrap(),
            CitedEntryClass::Unresolved
        );
    }

    #[tokio::test]
    async fn classifier_legacy_candidate_pointer_proves_a_historical_generic_entry() {
        let db = classifier_db().await;
        let source = classifier_source(false);
        let digest = sha256_hex(source.as_bytes());
        insert_body(&db, CLASSIFIER_ARTIFACT, "body:historic", &source).await;
        // The artifact has since been edited to a comment source, so the
        // current body cannot prove the requested historical digest.
        insert_body(
            &db,
            CLASSIFIER_ARTIFACT,
            "body:current",
            &classifier_source(true),
        )
        .await;
        insert_candidate(
            &db,
            "candidate:generic",
            "create_note",
            "history:generic",
            "body:historic",
            &digest,
            None,
        )
        .await;
        let caller = crate::mcp::Caller::local();
        // The exact origin pointer plus a real `record.create` entry enables
        // the unchanged legacy replay.
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("create_note", &digest, "history:generic")
            )
            .await
            .unwrap(),
            CitedEntryClass::Other
        );
        // A different-source candidate cannot borrow the outcome.
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("create_note", &"f".repeat(64), "history:generic")
            )
            .await
            .unwrap(),
            CitedEntryClass::Unresolved
        );
    }

    #[tokio::test]
    async fn classifier_corrupt_or_wrong_source_candidate_reads_as_unresolved() {
        let db = classifier_db().await;
        let source = classifier_source(false);
        let digest = sha256_hex(source.as_bytes());
        insert_body(&db, CLASSIFIER_ARTIFACT, "body:historic", &source).await;
        // A comment body is current, so no current-body fallback can mask a
        // candidate verdict below.
        insert_body(
            &db,
            CLASSIFIER_ARTIFACT,
            "body:current",
            &classifier_source(true),
        )
        .await;
        // A wrong-source digest.
        insert_candidate(
            &db,
            "candidate:wrong",
            "create_note",
            "wrong:key",
            "body:historic",
            &"e".repeat(64),
            None,
        )
        .await;
        // A digest that matches but whose immutable body does not hash to it.
        insert_raw_event(
            &db,
            CLASSIFIER_ARTIFACT,
            "body:corrupt",
            Some(&json!({"body": "not the requested source"}).to_string()),
        )
        .await;
        insert_candidate(
            &db,
            "candidate:corrupt-body",
            "create_note",
            "corrupt:body",
            "body:corrupt",
            &digest,
            None,
        )
        .await;
        // A forged comment-origin candidate must not be an effect-null match.
        insert_candidate(
            &db,
            "candidate:comment",
            "create_note",
            "comment:key",
            "body:historic",
            &digest,
            Some("comment.create"),
        )
        .await;
        // Non-object JSON metadata must read as absent, not error.
        insert_raw_event(&db, CLASSIFIER_ARTIFACT, "candidate:malformed", Some("[]")).await;
        let caller = crate::mcp::Caller::local();
        for key in ["wrong:key", "corrupt:body", "comment:key", "malformed"] {
            let digest = if key == "wrong:key" {
                "e".repeat(64)
            } else {
                digest.clone()
            };
            assert_eq!(
                classify_cited_entry(
                    &db,
                    &caller,
                    &classifier_invocation("create_note", &digest, key)
                )
                .await
                .unwrap(),
                CitedEntryClass::Unresolved,
                "candidate {key} must stay unresolved"
            );
        }
    }

    #[tokio::test]
    async fn classifier_parses_html_without_a_descriptor_runtime_hint() {
        let db = classifier_db().await;
        let source = html_source_from_mdx(&classifier_source(true));
        let digest = sha256_hex(source.as_bytes());
        insert_body(&db, CLASSIFIER_ARTIFACT, "body:html", &source).await;
        let caller = crate::mcp::Caller::local();
        // No attestation: the absent runtime hint must not block actual HTML.
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("post", &digest, "html:unattested:comment")
            )
            .await
            .unwrap(),
            CitedEntryClass::Comment
        );
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("create_note", &digest, "html:unattested:other")
            )
            .await
            .unwrap(),
            CitedEntryClass::Other
        );
        insert_attestation(
            &db,
            CLASSIFIER_ARTIFACT,
            "attestation:html",
            "body:html",
            &digest,
            json!({"schema": "native.html.artifact-source.v1", "runtime": "native.html.v1"}),
        )
        .await;
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("post", &digest, "html:attested")
            )
            .await
            .unwrap(),
            CitedEntryClass::Comment
        );
    }

    #[tokio::test]
    async fn classifier_corrupt_source_payload_is_unresolved_without_error() {
        let db = classifier_db().await;
        // Valid JSON that is not an artifact body (a corrupt pointer target)
        // must read as absent rather than raising from JSON extraction.
        insert_raw_event(
            &db,
            CLASSIFIER_ARTIFACT,
            "body:broken",
            Some("\"not an artifact source\""),
        )
        .await;
        insert_attestation(
            &db,
            CLASSIFIER_ARTIFACT,
            "attestation:broken",
            "body:broken",
            &"b".repeat(64),
            json!({"schema": "native.mdx.artifact-source.v1"}),
        )
        .await;
        let caller = crate::mcp::Caller::local();
        assert_eq!(
            classify_cited_entry(
                &db,
                &caller,
                &classifier_invocation("create_note", &"b".repeat(64), "broken:source")
            )
            .await
            .unwrap(),
            CitedEntryClass::Unresolved
        );
    }
}
