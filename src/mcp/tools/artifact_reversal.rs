//! Engine reversal core for declared artifact writes (D7 slice U2a, internal only).
//!
//! Tests call [`revert_in`] directly; it has no tool surface. It reverses one
//! committed write the viewer owns, from any declaring package — installed
//! tabs today, other surfaces later: the host holds the original invocation's
//! key from the receipt, the engine derives the reverse itself from history,
//! and the result is an ordinary attributed write. Only `Restorable`
//! catalogue rows reverse; `Additive` rows refuse `not_reversible`. An undo
//! is never itself undoable.
//!
//! Undo works after the install is disabled or removed: there is no
//! install-guard check here (R5 ruled "works after disabled" for this slice).

use serde_json::{json, Value};
use sqlx::{Sqlite, Transaction};

use crate::authorization::Capability;
use crate::db::Db;
use crate::domain_transaction::FacetWrite;
use crate::error::{Error, Result};
use crate::query::cascade;
use crate::schema::spine_facet_column;
use crate::store::{append_in, AppendSpec};

use native_artifact_runtime::artifact_intents::{
    ArtifactIntentResult, ArtifactInvocation, CompetingActor, FacetVersion, IntentChange,
    IntentError,
};

use super::super::registry::Caller;

const TOOL: &str = "artifact_reversal";

// Inspect ONLY origin schema/closed-variant markers, never user body, title,
// package or key text. Enumerate ALL root origin members, including duplicate
// origins and schema markers, rather than a path-selected first occurrence;
// authoritative UniqueJson parsing belongs to the owned Body transaction.
const BODY_ORIGIN_RECOGNITION: &str = "CASE WHEN json_valid(payload) THEN
    CASE WHEN json_type(payload)='object' THEN
        EXISTS(SELECT 1 FROM json_each(payload) AS root
            WHERE root.key='origin' AND CASE WHEN root.type='object' THEN
                EXISTS(SELECT 1 FROM json_each(root.value) AS field
                    WHERE field.key='schema' AND field.type='text' AND field.value='native.body-effect-origin.v1')
                OR (EXISTS(SELECT 1 FROM json_each(root.value) AS field WHERE field.key='admission_pins' AND field.type='object')
                    AND EXISTS(SELECT 1 FROM json_each(root.value) AS field WHERE field.key='operation' AND field.type='text' AND field.value IN ('save','undo')))
                ELSE 0 END) ELSE 0 END ELSE 0 END";

#[cfg(test)]
mod dormant_body_reversal_tests {
    use super::*;

    #[tokio::test]
    async fn body_recognition_refuses_nonobject_paths_and_checks_all_variant_members() {
        let db = crate::create_database(":memory:").await.unwrap();
        for (payload, expected) in [
            ("not-json", 0),
            (
                r#"[ {"origin":{"schema":"native.body-effect-origin.v1"}} ]"#,
                0,
            ),
            (
                r#"{"origin":"native.body-effect-origin.v1","origin":17,"origin":null}"#,
                0,
            ),
            (
                r#"{"origin":{"operation":"legacy","admission_pins":{},"operation":"save"}}"#,
                1,
            ),
            (
                r#"{"origin":{"schema":"legacy"},"origin":{"schema":"native.body-effect-origin.v1"}}"#,
                1,
            ),
            (
                r#"{"origin":{"schema":"native.body-effect-origin.v1"},"origin":{"schema":"legacy"}}"#,
                1,
            ),
        ] {
            let hint: i64 = sqlx::query_scalar(&format!(
                "SELECT {BODY_ORIGIN_RECOGNITION} FROM (SELECT ? AS payload)"
            ))
            .bind(payload)
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(hint, expected);
        }
    }

    #[tokio::test]
    async fn body_recognition_never_matches_legacy_user_text() {
        let db = crate::create_database(":memory:").await.unwrap();
        for payload in [
            json!({"body":"native.body-effect-origin.v1", "origin":{"key":"name","after":"native.body-effect-origin.v1"}}),
            json!({"origin":{"artifact_id":"native.body-effect-origin.v1","entry_id":"save","idempotency_key":"undo"}}),
        ] {
            let hint: i64 = sqlx::query_scalar(&format!(
                "SELECT {BODY_ORIGIN_RECOGNITION} FROM (SELECT ? AS payload)"
            ))
            .bind(payload.to_string())
            .fetch_one(db.pool())
            .await
            .unwrap();
            assert_eq!(hint, 0);
        }
    }

    #[tokio::test]
    async fn malformed_and_duplicate_body_origins_never_use_generic_reversal() {
        for duplicate in [false, true] {
            let db = crate::create_database(":memory:").await.unwrap();
            let caller = Caller::local();
            let mut tools = crate::mcp::ToolRegistry::new();
            crate::mcp::register_surface_tools(&mut tools).unwrap();
            let mut ids = Vec::new();
            for name in ["artifact fixture", "target fixture"] {
                let record = tools.call(db.clone(),caller.clone(),"create_record",
                    json!({"type":"Document","kind":"note","name":name,"body":"base","reason":"Body refusal fixture"})).await.unwrap();
                ids.push(record["id"].as_str().unwrap().to_owned());
            }
            let artifact = &ids[0];
            let target = &ids[1];
            let origin = json!({"schema":"native.body-effect-origin.v1","operation":"save",
                "artifact_id":artifact,"entry_id":"save","idempotency_key":"forward","record_id":target,
                "source_digest":"a".repeat(64),"extra":"malformed"});
            let mut payload = json!({"body":"wrong","origin":origin}).to_string();
            if duplicate {
                payload = payload.replace(
                    r#""operation":"save""#,
                    r#""operation":"save","operation":"save""#,
                );
            }
            sqlx::query("INSERT INTO content_events(id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status) VALUES(?,?,'record.updated',?,?,?,1,'legacy_unknown')")
                .bind(uuid::Uuid::new_v4().to_string()).bind(target).bind(payload)
                .bind(caller.actor()).bind("2026-10-03T00:00:00Z").execute(db.write_pool()).await.unwrap();
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM content_events")
                .fetch_one(db.pool())
                .await
                .unwrap();
            let invocation = ArtifactInvocation {
                version: native_artifact_runtime::artifact_intents::INVOCATION_VERSION.into(),
                artifact_id: artifact.clone(),
                entry_id: "save".into(),
                source_digest: "a".repeat(64),
                slots: Default::default(),
                values: Default::default(),
                observed: Default::default(),
                idempotency_key: "undo".into(),
                gesture: None,
                include_next_plan: false,
                alpha_install_guard: None,
                reverses: Some(
                    native_artifact_runtime::artifact_intents::ReversalReference {
                        entry_id: "save".into(),
                        idempotency_key: "forward".into(),
                    },
                ),
            };
            let result = revert_invocation_in(&db, &caller, &invocation)
                .await
                .unwrap();
            let value = serde_json::to_value(result).unwrap();
            assert_eq!(value["status"], "rejected");
            assert_eq!(
                value["error"]["code"],
                if duplicate {
                    "body_stored_json"
                } else {
                    "origin_shape"
                }
            );
            let direct = revert_in(
                &db,
                &caller,
                ReversalRequest {
                    artifact_id: artifact.clone(),
                    record_id: target.clone(),
                    entry_id: "save".into(),
                    original_key: "forward".into(),
                    idempotency_key: "direct".into(),
                },
            )
            .await
            .unwrap();
            assert_eq!(
                serde_json::to_value(direct).unwrap()["error"]["code"],
                "body_unavailable"
            );
            assert_eq!(
                sqlx::query_scalar::<_, i64>("SELECT count(*) FROM content_events")
                    .fetch_one(db.pool())
                    .await
                    .unwrap(),
                count
            );
            assert_eq!(
                sqlx::query_scalar::<_, Option<String>>("SELECT body FROM records WHERE id=?")
                    .bind(target)
                    .fetch_one(db.pool())
                    .await
                    .unwrap(),
                Some("base".into())
            );
        }
    }
}

/// Row filter locating one original forward write for a reversal, shared by
/// the engine path below and the hosted gesture mint (D7 §4B.3, slice G3).
/// The SELECT list differs per caller — the engine also reads the payload,
/// the mint only the record — but the filter must stay identical, so it
/// lives here once. Like forward replay, it never resolves to an undo event
/// as the "original": only forward writes reverse.
///
/// The mint deliberately skips the engine's subsequent `source_digest`
/// post-check, and that is safe in both directions: a token minted past a
/// stale source is simply unused, because the engine refuses
/// `stale_source_digest` before it verifies any token; and a valid undo
/// always resolves to the same single row the engine then verifies against,
/// so no valid undo can lose its token.
pub const REVERSAL_ORIGINAL_FILTER: &str = "WHERE actor=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
            AND json_extract(payload,'$.origin.reverses') IS NULL
          ORDER BY seq LIMIT 2";

/// A host-held reversal handle: the original invocation this undoes, plus
/// this undo's own fresh key. The host never supplies a sequence token.
///
/// Public only so integration tests can call [`revert_in`] directly; there
/// is no tool surface for reversals in this slice.
#[derive(Clone, Debug)]
pub struct ReversalRequest {
    pub artifact_id: String,
    pub record_id: String,
    pub entry_id: String,
    pub original_key: String,
    pub idempotency_key: String,
}

/// Serve a reversal-mode tool invocation (D7 slice U2b). The envelope carries
/// no record and no slots, so the original is resolved across records from
/// (actor, artifact, original entry, original key): none is
/// `reversal_unknown`, more than one is `idempotency_conflict`, and the one
/// must name the presented `source_digest` in its stored origin — the current
/// render is never consulted, so editing the artifact does not strand an
/// undo. Attribution resolves through `reverses.event_id` to the original's
/// origin, which is why this request carries no package or guard field.
pub(super) async fn revert_invocation_in(
    db: &Db,
    caller: &Caller,
    invocation: &ArtifactInvocation,
) -> Result<ArtifactIntentResult> {
    let Some(reverses) = &invocation.reverses else {
        return Err(Error::engine("revert_invocation_in without reverses"));
    };
    // Bounded recognition only; no Body payload cell is fetched on the
    // preliminary pool snapshot. The kernel owns all authoritative rechecks.
    let body_hints: Vec<i64> = sqlx::query_scalar(&format!(
        "SELECT {BODY_ORIGIN_RECOGNITION} FROM content_events {REVERSAL_ORIGINAL_FILTER}"
    ))
    .bind(caller.actor())
    .bind(&invocation.artifact_id)
    .bind(&reverses.entry_id)
    .bind(&reverses.idempotency_key)
    .fetch_all(db.pool())
    .await?;
    if body_hints.iter().any(|hint| *hint != 0) {
        crate::mcp::registry::note_invoke_domain_owned();
        return Ok(
            match super::lifecycle::undo_body_from_artifact(db, caller, invocation).await? {
                super::lifecycle::ArtifactBodyOutcome::Committed { receipt } => *receipt,
                super::lifecycle::ArtifactBodyOutcome::Refused { code, message } => {
                    rejected(&invocation.idempotency_key, &code, message)
                }
            },
        );
    }
    let rows: Vec<(String, String)> = sqlx::query_as(&format!(
        "SELECT record_id, payload FROM content_events {REVERSAL_ORIGINAL_FILTER}"
    ))
    .bind(caller.actor())
    .bind(&invocation.artifact_id)
    .bind(&reverses.entry_id)
    .bind(&reverses.idempotency_key)
    .fetch_all(db.pool())
    .await?;
    // Fail closed on ambiguity: the envelope carries no record, so a key
    // that names more than one original cannot be undone, even though the
    // host's receipt handle knows the record. One forward key legitimately
    // spanning records is therefore un-undoable through this mode; carrying
    // the record would lift that at the cost of widening the envelope.
    if rows.len() > 1 {
        return Ok(rejected(
            &invocation.idempotency_key,
            "idempotency_conflict",
            "the original key names more than one invocation",
        ));
    }
    let Some((record_id, payload)) = rows.into_iter().next() else {
        return Ok(rejected(
            &invocation.idempotency_key,
            "reversal_unknown",
            "no matching original invocation to undo",
        ));
    };
    let stored: Value = serde_json::from_str(&payload)?;
    let named = stored
        .pointer("/origin/source_digest")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if named != invocation.source_digest {
        return Ok(rejected(
            &invocation.idempotency_key,
            "stale_source_digest",
            "the reversal names the original's source, not the current render",
        ));
    }
    // Effect-gesture check (D7 §4B, G2), action-scoped to a reversal so a
    // forward token cannot satisfy an undo. Verified before any write; a
    // bad or expired token refuses with zero writes. The reversal binds no
    // package (it carries none), but it binds its artifact, the original
    // entry, the resolved record as its target, the undo's own fresh key, and
    // the (empty) values digest, which is constant in reversal mode. A
    // reversal is always in enforcement scope (guarded): under the hosted
    // guarded-only mode a missing token is refused, like a package-claimed
    // forward.
    let gesture_evidence = match super::artifact_interactions::verify_effect_gesture(
        caller,
        crate::awareness::EFFECT_GESTURE_REVERSAL_ACTION,
        &invocation.artifact_id,
        None,
        None,
        &reverses.entry_id,
        std::slice::from_ref(&record_id),
        &invocation.idempotency_key,
        &super::artifact_interactions::invocation_values_digest(invocation),
        true,
    ) {
        super::artifact_interactions::GestureCheck::Absent => None,
        super::artifact_interactions::GestureCheck::Evidence(evidence) => Some(evidence),
        super::artifact_interactions::GestureCheck::Refused { code, message } => {
            return Ok(rejected(&invocation.idempotency_key, code, message));
        }
    };
    revert_in_inner(
        db,
        caller,
        ReversalRequest {
            artifact_id: invocation.artifact_id.clone(),
            record_id,
            entry_id: reverses.entry_id.clone(),
            original_key: reverses.idempotency_key.clone(),
            idempotency_key: invocation.idempotency_key.clone(),
        },
        gesture_evidence,
    )
    .await
}

/// Reverse one committed tab write inside one write transaction, following
/// D7 §2.3–§2.5. Every refusal below commits nothing.
///
/// Public only so integration tests can call it directly; there is no tool
/// surface for reversals in this slice.
pub async fn revert_in(
    db: &Db,
    caller: &Caller,
    request: ReversalRequest,
) -> Result<ArtifactIntentResult> {
    revert_in_inner(db, caller, request, None).await
}

/// The reversal proper, plus verified effect-gesture evidence to record on
/// the appended origin when the host presented a token (D7 §4B, G2). The
/// direct `revert_in` entry passes no evidence, so existing callers and
/// origins are byte-identical.
async fn revert_in_inner(
    db: &Db,
    caller: &Caller,
    request: ReversalRequest,
    gesture_evidence: Option<Value>,
) -> Result<ArtifactIntentResult> {
    if request.artifact_id.is_empty()
        || request.record_id.is_empty()
        || request.entry_id.is_empty()
        || request.original_key.is_empty()
        || request.idempotency_key.is_empty()
    {
        return Ok(rejected(
            &request.idempotency_key,
            "invalid_reversal",
            "the reversal handle is blank or too long",
        ));
    }
    let mut tx = crate::db::begin_write(db.write_pool()).await?;

    // Generic/direct reversal must not disclose a Body receipt or decode
    // its nullable inverse. Only the guarded invocation kernel may do that.
    let body_candidates: Vec<i64> = sqlx::query_scalar(&format!(
        "SELECT 1 FROM content_events
         WHERE actor=? AND record_id=?
         AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.artifact_id')=? ELSE 0 END
         AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.entry_id')=? ELSE 0 END
         AND CASE WHEN json_valid(payload) THEN json_extract(payload,'$.origin.idempotency_key')=? ELSE 0 END
         AND ({BODY_ORIGIN_RECOGNITION})
         ORDER BY seq LIMIT 2"
    )).bind(caller.actor()).bind(&request.record_id).bind(&request.artifact_id)
        .bind(&request.entry_id).bind(&request.original_key).fetch_all(&mut *tx).await?;
    if !body_candidates.is_empty() {
        tx.rollback().await?;
        return Ok(rejected(
            &request.idempotency_key,
            "body_unavailable",
            "Body reversal requires the guarded dormant kernel",
        ));
    }

    // Same undo key, same original: replay the stored reversal without
    // appending. `before`/`after` describe the key as it stands now; the
    // token is the one the undo left, reconstructed from the undo seq.
    if let Some(replayed) =
        reversal_replay_in(&mut tx, caller, &request.record_id, &request).await?
    {
        return Ok(replayed);
    }
    // The original forward event, scoped exactly like forward replay. Any
    // other actor's key matches nothing here, which is the `reversal_unknown`
    // that also resolves a host-side uncertain outcome honestly.
    let Some(original) = find_original_in(&mut tx, caller, &request.record_id, &request).await?
    else {
        return Ok(rejected(
            &request.idempotency_key,
            "reversal_unknown",
            "no matching original invocation to undo",
        ));
    };
    // An undo is never itself undoable in v1.
    if original.has_reverses {
        return Ok(rejected(
            &request.idempotency_key,
            "not_reversible",
            "a reversal cannot itself be reversed",
        ));
    }
    // The catalogue owns whether the effect reverses. Spine lifecycle writes
    // take the tasks arm whatever value they carried (§2.2 lists terminal
    // states as restorable); anything without a row, including comment
    // creates, refuses `not_reversible`.
    let is_restorable = restorable(&original);
    if !is_restorable {
        return Ok(rejected(
            &request.idempotency_key,
            "not_reversible",
            "this effect has no reversal in this slice",
        ));
    };
    // Once-only (§2.3a case 3, before CAS): a different key for an
    // already-reversed original returns `already_reversed` with zero writes.
    // Each original reverses at most once. Entry-scoped like forward replay,
    // so the same key reused under a different entry is a different original.
    let already: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events
          WHERE record_id=? AND actor=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.reverses.idempotency_key')=?
            AND json_extract(payload,'$.origin.reverses.entry_id')=?
            AND json_extract(payload,'$.origin.reverses') IS NOT NULL)",
    )
    .bind(&request.record_id)
    .bind(caller.actor())
    .bind(&request.artifact_id)
    .bind(&request.original_key)
    .bind(&request.entry_id)
    .fetch_one(&mut *tx)
    .await?;
    if already {
        return Ok(rejected(
            &request.idempotency_key,
            "already_reversed",
            "this invocation was already reversed",
        ));
    }
    // CAS from the original event's own seq: the token the original left.
    // A later change — by anyone, including the viewer elsewhere — returns
    // the existing `Conflict` shape instead of overwriting. There is no
    // "undo anyway".
    let expected = if original.shape.is_spine() {
        FacetVersion::Record {
            event_seq: original.seq,
        }
    } else {
        FacetVersion::Observation {
            event_seq: original.seq,
        }
    };
    let current = super::artifact_interactions::current_facet_version(
        &mut tx,
        &request.record_id,
        &original.key,
        original.shape.spine_column(),
    )
    .await?;
    if current != expected {
        let (conflicting_event_id, actor) = super::artifact_interactions::conflicting_event_in(
            &mut tx,
            &request.record_id,
            &original.key,
            &current,
            original.shape.spine_column(),
        )
        .await?;
        let competing_actor = match actor.as_deref() {
            Some(actor) => super::history::disclosed_actor_identity_in(&mut tx, caller, actor)
                .await?
                .map(|(id, display_name)| CompetingActor { id, display_name }),
            None => None,
        };
        return Ok(ArtifactIntentResult::conflict(
            &request.idempotency_key,
            IntentError::retryable(
                "facet_conflict",
                format!(
                    "facet '{}' on record {} moved since it was read",
                    original.key, request.record_id
                ),
            ),
            &current,
            &conflicting_event_id,
            competing_actor,
        ));
    }
    // The reverse value from history: the value immediately before the
    // original event (prior observation row for open facets; the record's
    // projected field at `original seq − 1` for spine fields).
    let prior = prior_value_in(&mut tx, &request.record_id, &original).await?;
    if original.shape.is_spine() && prior.is_none() {
        return Ok(rejected(
            &request.idempotency_key,
            "unsupported_facet",
            "spine facets cannot be cleared through an artifact reversal",
        ));
    }
    // Authority as the viewer, now: View plus Edit on the target. No
    // install check: undoing a committed tab write survives disabling.
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL)",
    )
    .bind(&request.record_id)
    .fetch_one(&mut *tx)
    .await?;
    if !exists {
        return Ok(rejected(
            &request.idempotency_key,
            "missing_record",
            "the reversed record does not exist",
        ));
    }
    for required in [Capability::View, Capability::Edit] {
        if !super::can_record_in(&mut tx, caller, &request.record_id, required).await? {
            return Ok(rejected(
                &request.idempotency_key,
                "permission_denied",
                "the authenticated principal may not reverse this record",
            ));
        }
    }
    // Normal governance on the restored value: schema, vocabulary and the
    // required-facet bracket every other record-writing tool applies. A prior
    // value that is no longer admissible refuses honestly.
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;
    let meta: Option<(String, Option<String>)> =
        sqlx::query_as("SELECT type, kind FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&request.record_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((record_type, record_kind)) = meta else {
        return Ok(rejected(
            &request.idempotency_key,
            "missing_record",
            "the reversed record does not exist",
        ));
    };
    let mut governed: Vec<FacetWrite> = match (&original.shape, &prior) {
        (OriginalShape::Spine { .. }, Some(value)) => vec![FacetWrite {
            key: original.key.clone(),
            value: value.clone(),
            vocab_ref: None,
            time_type: None,
        }],
        (OriginalShape::Spine { .. }, None) => {
            return Err(Error::engine("spine reversal without a prior value"));
        }
        (OriginalShape::Open, Some(value)) => {
            match super::lifecycle::parse_facet_entry(TOOL, &original.key, value, false) {
                Ok(Some(facet)) => vec![facet],
                Ok(None) => vec![],
                Err(error) => {
                    return Ok(rejected(
                        &request.idempotency_key,
                        "unsupported_facet",
                        error.to_string(),
                    ));
                }
            }
        }
        (OriginalShape::Open, None) => vec![],
        (OriginalShape::Other, _) => {
            return Err(Error::engine("unclassifiable original reached governance"));
        }
    };
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
            return Ok(rejected(
                &request.idempotency_key,
                "schema_violation",
                error.to_string(),
            ));
        }
    }
    let before_required = super::lifecycle::required_violations_in(
        &mut tx,
        &schema_rows,
        &[request.record_id.as_str()],
    )
    .await?;
    // One ordinary event of the same type as a forward write, so
    // projections are unchanged. Its origin carries this undo's own key in
    // `idempotency_key` and the original in `reverses` (§2.3a).
    let before = super::artifact_interactions::current_facet_value(
        &mut tx,
        &request.record_id,
        &original.key,
        original.shape.spine_column(),
    )
    .await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    let mut origin = json!({
        "artifact_id": request.artifact_id,
        "entry_id": request.entry_id,
        "source_digest": original.source_digest,
        "idempotency_key": request.idempotency_key,
        "gesture": "submit",
        "alpha_install_guard": Value::Null,
        "via": "host",
        "reverses": {
            "entry_id": request.entry_id,
            "idempotency_key": request.original_key,
            "event_id": original.event_id,
        },
    });
    if let Some(evidence) = gesture_evidence {
        origin["gesture_evidence"] = evidence;
    }
    let after = match governed.first() {
        Some(facet) if facet.time_type.is_some() => Some(facet.value.clone()),
        _ => prior.clone(),
    };
    let mut spec = match (&original.shape, governed.first()) {
        (OriginalShape::Spine { .. }, _) => {
            let column = original
                .shape
                .spine_column()
                .expect("a spine reversal names its column");
            let prior = prior.clone().unwrap_or(Value::Null);
            AppendSpec {
                record_id: request.record_id.clone(),
                event_type: "record.updated".into(),
                payload: json!({
                    column: prior,
                    "reason": format!("Artifact reversal of '{}'", request.entry_id),
                }),
                actor: Some(caller.actor().into()),
            }
        }
        (OriginalShape::Open, Some(facet)) => {
            crate::domain_transaction::facet_set_spec(&request.record_id, facet, caller.actor())
        }
        (OriginalShape::Open, None) => AppendSpec {
            record_id: request.record_id.clone(),
            event_type: "facet.unset".into(),
            payload: json!({ "key": original.key }),
            actor: Some(caller.actor().into()),
        },
        (OriginalShape::Other, _) => {
            return Err(Error::engine("unclassifiable original reached append"));
        }
    };
    if let Some(payload) = spec.payload.as_object_mut() {
        payload.insert("origin".into(), origin);
    }
    append_in(db, &mut tx, spec, &mut act_alloc).await?;
    let after_required = super::lifecycle::required_violations_in(
        &mut tx,
        &schema_rows,
        &[request.record_id.as_str()],
    )
    .await?;
    if let Err(error) =
        super::lifecycle::assert_required_not_worsened(TOOL, &before_required, &after_required)
    {
        return Ok(rejected(
            &request.idempotency_key,
            "required_facet_missing",
            error.to_string(),
        ));
    }
    // The token this undo LEFT, read inside the transaction that produced it.
    let version = super::artifact_interactions::current_facet_version(
        &mut tx,
        &request.record_id,
        &original.key,
        original.shape.spine_column(),
    )
    .await?;
    db.commit_content(tx).await?;
    Ok(ArtifactIntentResult::committed(
        &request.idempotency_key,
        vec![IntentChange {
            record_id: request.record_id,
            key: original.key,
            before,
            after,
            version: Some(version.encode()),
        }],
    ))
}
fn rejected(key: &str, code: &str, message: impl Into<String>) -> ArtifactIntentResult {
    ArtifactIntentResult::rejected(key, IntentError::new(code, message))
}

/// A decoded original forward write: the facet key it moved and how.
struct Original {
    seq: i64,
    event_id: String,
    event_type: String,
    key: String,
    shape: OriginalShape,
    has_reverses: bool,
    source_digest: String,
}

enum OriginalShape {
    Open,
    Spine { column: &'static str },
    Other,
}

impl OriginalShape {
    fn is_spine(&self) -> bool {
        matches!(self, Self::Spine { .. })
    }

    fn spine_column(&self) -> Option<&'static str> {
        match self {
            Self::Spine { column, .. } => Some(column),
            _ => None,
        }
    }
}

fn decode_stored(stored: &str) -> Value {
    match serde_json::from_str(stored) {
        Ok(Value::String(_)) | Ok(Value::Number(_)) | Ok(Value::Object(_)) => {
            serde_json::from_str(stored).unwrap_or(Value::String(stored.into()))
        }
        _ => Value::String(stored.into()),
    }
}

async fn find_original_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    record_id: &str,
    request: &ReversalRequest,
) -> Result<Option<Original>> {
    let row: Option<(i64, String, String, String)> = sqlx::query_as(
        "SELECT seq, id, type, payload FROM content_events
          WHERE record_id=? AND actor=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.entry_id')=?
          ORDER BY seq LIMIT 1",
    )
    .bind(record_id)
    .bind(caller.actor())
    .bind(&request.original_key)
    .bind(&request.artifact_id)
    .bind(&request.entry_id)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((seq, event_id, event_type, payload)) = row else {
        return Ok(None);
    };
    let stored: Value = serde_json::from_str(&payload)?;
    let origin = stored.get("origin");
    let has_reverses = origin.is_some_and(|origin| !origin.get("reverses").is_none());
    let source_digest = origin
        .and_then(|origin| origin.get("source_digest"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let shape = match event_type.as_str() {
        "facet.set" => match stored.get("key").and_then(Value::as_str) {
            Some(_) => OriginalShape::Open,
            None => OriginalShape::Other,
        },
        "facet.unset" => match stored.get("key").and_then(Value::as_str) {
            Some(_) => OriginalShape::Open,
            None => OriginalShape::Other,
        },
        "record.updated" => {
            let found: Option<(&'static str, &Value)> = stored.as_object().and_then(|object| {
                object.iter().find_map(|(key, value)| {
                    if *key == "reason" || *key == "origin" {
                        return None;
                    }
                    // The title column is not a spine facet key, so it
                    // needs its own arm here (task `da148be`): a
                    // `record.updated` carrying `name` reverses by
                    // restoring the prior title like any spine write.
                    if key == "name" {
                        return Some(("name", value));
                    }
                    spine_facet_column(key).map(|column| (column, value))
                })
            });
            match found {
                Some((column, _)) => OriginalShape::Spine { column },
                None => OriginalShape::Other,
            }
        }
        _ => OriginalShape::Other,
    };
    let key = match &shape {
        OriginalShape::Open => stored
            .get("key")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        OriginalShape::Spine { column, .. } => column.to_string(),
        OriginalShape::Other => String::new(),
    };
    Ok(Some(Original {
        seq,
        event_id,
        event_type,
        key,
        shape,
        has_reverses,
        source_digest,
    }))
}
/// Whether the original is a restorable write, decided by the catalogue row
/// for its stored event type and key.
fn restorable(original: &Original) -> bool {
    matches!(
        super::tab_effect_catalogue::reversal_class_for_write(&original.event_type, &original.key),
        Some(super::tab_effect_catalogue::ReversalClass::Restorable)
    )
}

/// Same undo key, same original: settle the stored reversal without
/// appending. Same undo key, different original or record (§2.3a case 2):
/// zero writes. The lookup is deliberately not record-scoped: the undo key
/// names one reversal, wherever it landed.
async fn reversal_replay_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    record_id: &str,
    request: &ReversalRequest,
) -> Result<Option<ArtifactIntentResult>> {
    let row: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT seq, record_id, payload FROM content_events
          WHERE actor=?
            AND json_extract(payload,'$.origin.artifact_id')=?
            AND json_extract(payload,'$.origin.idempotency_key')=?
            AND json_extract(payload,'$.origin.reverses') IS NOT NULL
          ORDER BY seq LIMIT 1",
    )
    .bind(caller.actor())
    .bind(&request.artifact_id)
    .bind(&request.idempotency_key)
    .fetch_optional(&mut **tx)
    .await?;
    let Some((undo_seq, undo_record_id, payload)) = row else {
        return Ok(None);
    };
    let stored: Value = serde_json::from_str(&payload)?;
    let reverses = stored.pointer("/origin/reverses");
    let same = undo_record_id == record_id
        && reverses
            .and_then(|value| value.get("entry_id"))
            .and_then(Value::as_str)
            == Some(request.entry_id.as_str())
        && reverses
            .and_then(|value| value.get("idempotency_key"))
            .and_then(Value::as_str)
            == Some(request.original_key.as_str());
    if !same {
        return Ok(Some(rejected(
            &request.idempotency_key,
            "idempotency_conflict",
            "the idempotency key was already used for a different reversal",
        )));
    }
    let (key, spine, after) = replayed_undo_state(&stored);
    let before =
        super::artifact_interactions::current_facet_value(&mut *tx, record_id, &key, spine).await?;
    let version = if spine.is_some() {
        FacetVersion::Record {
            event_seq: undo_seq,
        }
    } else {
        FacetVersion::Observation {
            event_seq: undo_seq,
        }
    };
    Ok(Some(ArtifactIntentResult::committed(
        &request.idempotency_key,
        vec![IntentChange {
            record_id: record_id.into(),
            key,
            before,
            after,
            version: Some(version.encode()),
        }],
    )))
}

/// Read the restored state back off a stored undo payload: its key, its
/// spine column if any, and the value it left (`None` for an unset).
fn replayed_undo_state(payload: &Value) -> (String, Option<&'static str>, Option<Value>) {
    if let Some(key) = payload.get("key").and_then(Value::as_str) {
        let after = match payload.get("value") {
            Some(Value::String(text)) => Some(decode_stored(text)),
            Some(value) if !value.is_null() => Some(value.clone()),
            _ => None,
        };
        return (key.into(), None, after);
    }
    if let Some(object) = payload.as_object() {
        for (key, value) in object {
            if key == "reason" || key == "origin" {
                continue;
            }
            // The title column is not a spine facet key; it needs its own
            // arm here, mirroring `find_original_in` (task `da148be`).
            if key == "name" {
                let after = match value {
                    Value::String(text) => Some(decode_stored(text)),
                    _ if !value.is_null() => Some(value.clone()),
                    _ => None,
                };
                return ("name".to_string(), Some("name"), after);
            }
            if let Some(column) = spine_facet_column(key) {
                let after = match value {
                    Value::String(text) => Some(decode_stored(text)),
                    _ if !value.is_null() => Some(value.clone()),
                    _ => None,
                };
                return (column.to_string(), Some(column), after);
            }
        }
    }
    (String::new(), None, None)
}

/// The value immediately before the original event: the prior observation
/// row for open facets, or the record's projected spine field at
/// `original seq − 1`. `None` means there was nothing to restore (an unset
/// for open facets; refused for spine facets, which cannot clear).
async fn prior_value_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    original: &Original,
) -> Result<Option<Value>> {
    match &original.shape {
        OriginalShape::Open => {
            let row: Option<(Option<String>, String)> = sqlx::query_as(
                "SELECT value, op FROM facet_observations
                  WHERE record_id=? AND key=? AND event_seq < ?
                  ORDER BY event_seq DESC LIMIT 1",
            )
            .bind(record_id)
            .bind(&original.key)
            .bind(original.seq)
            .fetch_optional(&mut **tx)
            .await?;
            match row {
                Some((Some(value), op)) if op == "set" => Ok(Some(decode_stored(&value))),
                _ => Ok(None),
            }
        }
        OriginalShape::Spine { column, .. } => {
            spine_value_before_in(tx, record_id, column, original.seq).await
        }
        OriginalShape::Other => Ok(None),
    }
}

/// Replay the record column history below one seq: the latest
/// `record.updated` value, else the creation fields, else nothing.
async fn spine_value_before_in(
    tx: &mut Transaction<'static, Sqlite>,
    record_id: &str,
    column: &str,
    before_seq: i64,
) -> Result<Option<Value>> {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events
          WHERE record_id=? AND seq < ? AND type IN ('record.updated', 'record.created')
          ORDER BY seq DESC",
    )
    .bind(record_id)
    .bind(before_seq)
    .fetch_all(&mut **tx)
    .await?;
    for payload in rows {
        let stored: Value = serde_json::from_str(&payload)?;
        for location in [&stored].into_iter().chain(stored.get("fields")) {
            if let Some(value) = location.get(column) {
                if value.is_null() {
                    continue;
                }
                return Ok(Some(match value {
                    Value::String(text) => decode_stored(text),
                    _ => value.clone(),
                }));
            }
        }
    }
    Ok(None)
}
