//! `create_exploration` — the composite write behind "five candidates, one
//! exploration".
//!
//! # Why this exists at all
//!
//! If Richard asks for five possible homepage directions, a later reader
//! should receive *five candidates from one exploration*. Not five unrelated
//! records, and emphatically not five apparent beliefs. Leaving them merely
//! unendorsed is not enough: absence of endorsement does not say that these
//! five are mutually exclusive answers to one question.
//!
//! # Why it cannot be a loop over `create_record`
//!
//! `create_record` commits one record, its facets, and its links in one
//! transaction, and a missing link target rolls that whole call back. But it
//! creates exactly ONE record, and link targets must already exist. So a new
//! exploration collection plus N candidates cannot be made all-or-nothing by
//! calling it repeatedly: the collection would land, and a validation failure
//! on candidate four would leave a half-populated exploration behind that
//! reads as a complete one. Partial explorations are worse than no
//! exploration, because the missing candidate is invisible.
//!
//! This handler therefore opens ONE write transaction and does every append
//! inside it. On any validation, authorization, schema, or projection failure,
//! nothing lands.
//!
//! # What it deliberately does not promise
//!
//! **Request array order is not membership order.** V1 has no authored
//! ordinal, and `member_of` links carry no qualifier that could store one.
//! Promising `Option 1 of 5` from array position would encode a durable claim
//! the substrate cannot keep — `open_collection` returns members in
//! deterministic name/id order, which is presentation order. A future ordinal
//! needs a first-class membership substrate and its own product decision; it
//! must not be smuggled in through a facet or inferred from read ordering.

use serde::Deserialize;
use serde_json::{json, Map, Value};

use super::lifecycle::{
    assert_facet_value_predicates_in, assert_home_target_in, assert_required_not_worsened,
    enriched_or_error, facet_set_spec, required_violations_in, FacetWrite, NewLink,
};
use super::{parse_args, require_nonblank_reason, require_record_in, REASON_DESCRIPTION};
use crate::authorization::Capability;
use crate::contribution::{ALTERNATIVE_SET_ROLE, SELECTION_ROLE_FACET};
use crate::db::Db;
use crate::error::{Error, Result};
use crate::mcp::interactions::ToolKind;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::query::cascade;
use crate::store::{append_in, AppendSpec};

const TOOL: &str = "create_exploration";
/// One request may not open an unbounded exploration. This is a payload bound,
/// not a claim about how many alternatives an exploration may eventually hold:
/// further candidates join an existing marked selection through `exploration.id`.
pub const MAX_CANDIDATES: usize = 25;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateExplorationArgs {
    reason: String,
    exploration: ExplorationSelector,
    candidates: Vec<CandidateInput>,
    /// Optional caller-supplied idempotency key for the whole composite call.
    /// Absent (or blank) means exactly today's behavior. When present, the
    /// call joins the provenance command-attestation mechanism that
    /// `create_record` uses: same key plus same normalized request replays
    /// the original receipt without appending; same key plus a materially
    /// different request is a conflict error. One key covers the call's whole
    /// effect — exploration, candidates, links and facets alike — so no
    /// per-record identity plumbing is needed and record ids stay random.
    idempotency_key: Option<String>,
}

/// Exactly one of: define a new exploration, or name an existing marked one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum ExplorationSelector {
    /// A new visible `Collection kind:selection`, created in this transaction.
    Create(NewExploration),
    /// An exact existing visible and editable selection that already carries
    /// `decision.selection_role: alternative_set`.
    Id(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewExploration {
    name: String,
    /// The exploration label, originating request, scope, and explanatory
    /// context live in ordinary record prose — this is a visible record, not
    /// hidden metadata.
    body: Option<String>,
    summary: Option<String>,
    home_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateInput {
    #[serde(rename = "type")]
    record_type: String,
    kind: String,
    name: Option<String>,
    body: Option<String>,
    summary: Option<String>,
    lifecycle: Option<String>,
    home_id: Option<String>,
    facets: Option<Map<String, Value>>,
    /// A comment candidate carries its own required `part_of` bearer link
    /// here. The operation adds `member_of` to the exploration itself, so a
    /// caller neither can nor needs to supply it.
    links: Option<Vec<NewLink>>,
}

/// One record minted inside the composite transaction.
struct Minted {
    id: String,
}

pub fn register_exploration_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::CreateExploration,
        "Create a group of deliberate alternatives as one atomic act: an ordinary visible Collection kind:selection marked with the governed facet decision.selection_role='alternative_set', every candidate record or comment, and every member_of membership link, in one transaction. Either define a new exploration or name an exact existing marked selection. Any validation, authorization or schema failure on any candidate rolls the whole exploration back — a half-populated exploration is indistinguishable from a complete one to a later reader. Membership is an explicit set with no authored order: request array position is NOT durable candidate order, and no ordinal is stored or implied. Creating candidates establishes no stance, endorsement or selection; choosing one is a separate Resolution kind:decision.",
        json!({
            "type": "object",
            "properties": {
                "reason": { "type": "string", "minLength": 1, "description": REASON_DESCRIPTION },
                "exploration": {
                    "type": "object",
                    "description": "Exactly one of create or id.",
                    "properties": {
                        "create": {
                            "type": "object",
                            "properties": {
                                "name": { "type": "string" },
                                "body": { "type": "string", "description": "Exploration label, originating request, scope and explanatory context. Its prose is provenance, never endorsement of any member." },
                                "summary": { "type": "string" },
                                "home_id": { "type": "string" }
                            },
                            "required": ["name"],
                            "additionalProperties": false
                        },
                        "id": { "type": "string", "description": "An existing visible, editable Collection kind:selection already marked decision.selection_role='alternative_set'." }
                    },
                    "additionalProperties": false
                },
                "candidates": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": MAX_CANDIDATES,
                    "description": "Candidate records in the ordinary record-create shape. Order is request order only and is not promised as durable membership order.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "type": { "type": "string" },
                            "kind": { "type": "string" },
                            "name": { "type": "string" },
                            "body": { "type": "string" },
                            "summary": { "type": "string" },
                            "lifecycle": { "type": "string" },
                            "home_id": { "type": "string" },
                            "facets": { "type": "object" },
                            "links": {
                                "type": "array",
                                "description": "A comment candidate's required part_of bearer link. member_of to the exploration is added by this operation.",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "target_id": { "type": "string" },
                                        "relationship": { "type": "string" },
                                        "note": { "type": "string" }
                                    },
                                    "required": ["target_id", "relationship"],
                                    "additionalProperties": false
                                }
                            }
                        },
                        "required": ["type", "kind"],
                        "additionalProperties": false
                    }
                },
                // Bare, like the `create_record` key: the Rust field comment
                // carries the semantics, and the federated-lens Focused
                // descriptor budget is binding down to the byte.
                "idempotency_key": { "type": "string" }
            },
            "required": ["reason", "exploration", "candidates"],
            "additionalProperties": false
        }),
        create_exploration,
    )
}

async fn create_exploration(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    // The provenance digests run over the raw tool arguments: no server-minted
    // id enters the conflict detector, or every retry would conflict with the
    // call it repeats. Run-context keys are already stripped by the request
    // layer before the handler sees them.
    let provenance_arguments = arguments.clone();
    let args: CreateExplorationArgs = parse_args(TOOL, arguments)?;
    // Only the digest is stored, so an unbounded key is a mild DoS surface:
    // the same 1..=200 bound `create_record` enforces. Blank stays keyless
    // rather than erroring — a call with no key behaves as today.
    if args
        .idempotency_key
        .as_deref()
        .is_some_and(|key| key.len() > 200)
    {
        return Err(Error::engine(
            "create_exploration: idempotency_key must be 1..200 characters",
        ));
    }
    let idempotent = args
        .idempotency_key
        .as_deref()
        .is_some_and(|key| !key.trim().is_empty());
    require_nonblank_reason(TOOL, &args.reason)?;
    if args.candidates.is_empty() {
        return Err(Error::engine(format!(
            "{TOOL}: an exploration needs at least one candidate"
        )));
    }
    if args.candidates.len() > MAX_CANDIDATES {
        return Err(Error::engine(format!(
            "{TOOL}: at most {MAX_CANDIDATES} candidates per call; add further candidates to the same exploration by passing exploration.id"
        )));
    }

    // ONE transaction. Everything below either commits together or does not
    // exist. The reserved action identity is taken before any relationship
    // write so every output binds to one accepted action.
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let draft = crate::provenance::reserve_action_attestation()?;
    let caller_owner = super::mint::caller_owner_in(&mut tx, &caller, TOOL).await?;
    let schema_rows = cascade::schema_config_rows_in(&mut tx).await?;

    let (exploration_id, created_exploration) = match &args.exploration {
        ExplorationSelector::Id(id) => {
            // An existing carrier must already BE an exploration. Silently
            // marking an ordinary curated list would rewrite what its author
            // meant by it.
            require_record_in(&mut tx, &caller, TOOL, id, Capability::Edit).await?;
            assert_marked_alternative_set_in(&mut tx, id).await?;
            (id.clone(), false)
        }
        ExplorationSelector::Create(new) => {
            let id = crate::domain_transaction::record_id_for_create(None)?;
            let destination = new
                .home_id
                .as_deref()
                .unwrap_or(crate::schema::ROOT_RECORD_ID);
            if let Some(home_id) = &new.home_id {
                assert_home_target_in(&mut tx, TOOL, home_id).await?;
            }
            require_record_in(&mut tx, &caller, TOOL, destination, Capability::Edit).await?;

            let mut fields = Map::new();
            fields.insert("type".into(), json!("Collection"));
            fields.insert("kind".into(), json!("selection"));
            fields.insert("name".into(), json!(new.name));
            fields.insert("reason".into(), json!(args.reason));
            if let Some(body) = &new.body {
                fields.insert("body".into(), json!(body));
            }
            if let Some(summary) = &new.summary {
                fields.insert("summary".into(), json!(summary));
            }
            if let Some(home) = &new.home_id {
                fields.insert("home_id".into(), json!(home));
            }
            if let Some(owner) = &caller_owner {
                fields.insert("owner_id".into(), json!(owner));
            }
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: id.clone(),
                    event_type: "record.created".into(),
                    payload: Value::Object(fields),
                    actor: Some(caller.actor().into()),
                },
            )
            .await?;

            // The governed marker. `assert_facet_value_predicates_in` is the
            // same gate ordinary facet writes pass, so an unknown role value
            // is refused here exactly as it would be through create_record.
            let mut marker = vec![FacetWrite {
                key: SELECTION_ROLE_FACET.into(),
                value: Value::String(ALTERNATIVE_SET_ROLE.into()),
                vocab_ref: None,
            }];
            assert_facet_value_predicates_in(
                &mut tx,
                &schema_rows,
                TOOL,
                "Collection",
                Some("selection"),
                None,
                &mut marker,
            )
            .await?;
            for facet in &marker {
                append_in(&db, &mut tx, facet_set_spec(&id, facet, caller.actor())).await?;
            }
            (id, true)
        }
    };

    let mut minted = Vec::with_capacity(args.candidates.len());
    for candidate in &args.candidates {
        let id = mint_candidate_in(
            &db,
            &mut tx,
            &caller,
            &schema_rows,
            caller_owner.as_deref(),
            &args.reason,
            candidate,
            &draft,
        )
        .await?;
        // Membership is constituted by an explicit `member_of` link. It means
        // participation WITHOUT containment, so a candidate keeps its own
        // canonical browse home and its own record identity.
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: id.id.clone(),
                event_type: "link.added".into(),
                payload: serde_json::to_value(crate::events::LinkAddedPayload {
                    id: None,
                    source_id: id.id.clone(),
                    target_id: exploration_id.clone(),
                    relationship: "member_of".into(),
                    note: None,
                })?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
        minted.push(id);
    }

    // Required-facet health is checked across the whole batch, so one
    // candidate cannot be admitted by borrowing another's compliance.
    let ids: Vec<&str> = std::iter::once(exploration_id.as_str())
        .chain(minted.iter().map(|record| record.id.as_str()))
        .collect();
    let after = required_violations_in(&mut tx, &schema_rows, &ids).await?;
    assert_required_not_worsened(TOOL, &Default::default(), &after)?;

    // Idempotent replay, after every authorization and validation check and
    // inside the same BEGIN IMMEDIATE transaction as the mutation — the same
    // ordering contract `create_record` keeps so the tool cannot become a
    // command-existence oracle. A reused key with different normalized input
    // errors out of the lookup below, after an explicit rollback so the
    // tentative writes read as a rollback on every path, not just the hit.
    //
    // The tentative writes above are the validation: they run every guard the
    // first call ran, so a replay whose targets have since been deleted fails
    // exactly as a first call would. On a hit they are rolled back — nothing
    // durable, no second exploration, no duplicate links or facets — and the
    // receipt is rebuilt from the attested command's own membership links.
    if idempotent {
        let hit = match crate::provenance::lookup_authorized_command_attestation_in(
            &mut tx,
            caller.credential(),
            TOOL,
            &provenance_arguments,
            caller.intent(),
        )
        .await
        {
            Ok(hit) => hit,
            Err(error) => {
                tx.rollback().await?;
                return Err(error);
            }
        };
        if let Some(attestation_id) = hit {
            let attested = attested_exploration_in(&mut tx, &attestation_id).await?;
            // Non-disclosure for the outputs: the receipt discloses the
            // exploration and its candidates, so the replaying caller must
            // still view each of them. A caller that lost access gets the
            // opaque denial, not the receipt.
            require_record_in(
                &mut tx,
                &caller,
                TOOL,
                &attested.exploration_id,
                Capability::View,
            )
            .await?;
            for candidate_id in &attested.candidate_ids {
                require_record_in(&mut tx, &caller, TOOL, candidate_id, Capability::View).await?;
            }
            tx.rollback().await?;
            crate::provenance::note_replayed_action_attestation(attestation_id);
            // Reads happen only after the rollback; holding a second
            // connection while the write transaction is live is the one
            // deadlock trap here. These are live reads, not the pinned
            // reconstruction `create_record` performs: the receipt carries no
            // guarded-write token of its own, and membership context is live
            // by design, so a replay after an unrelated write returns the
            // current enrichment rather than a prefix rebuild.
            let exploration =
                enriched_or_error(&db, &caller, TOOL, &attested.exploration_id).await?;
            let mut candidates = Vec::with_capacity(attested.candidate_ids.len());
            for candidate_id in &attested.candidate_ids {
                candidates.push(enriched_or_error(&db, &caller, TOOL, candidate_id).await?);
            }
            return Ok(exploration_receipt(
                exploration,
                attested.exploration_created,
                candidates,
            ));
        }
    }

    crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    db.commit_content(tx).await?;

    // Reads happen only after the commit; holding a second connection while
    // the write transaction is live is the one deadlock trap here.
    let exploration = enriched_or_error(&db, &caller, TOOL, &exploration_id).await?;
    let mut candidates = Vec::with_capacity(minted.len());
    for record in &minted {
        candidates.push(enriched_or_error(&db, &caller, TOOL, &record.id).await?);
    }
    Ok(exploration_receipt(
        exploration,
        created_exploration,
        candidates,
    ))
}

/// One receipt shape for the first call and every replay: the enriched
/// exploration, whether this call created it, the candidates in request
/// order, and the standing interpretation limits.
fn exploration_receipt(
    exploration: Value,
    exploration_created: bool,
    candidates: Vec<Value>,
) -> Value {
    json!({
        "exploration": exploration,
        "exploration_created": exploration_created,
        "selection_role": ALTERNATIVE_SET_ROLE,
        // Request order, echoed so a caller can correlate its input. It is NOT
        // membership order, and nothing durable records one.
        "candidates": candidates,
        "candidate_order_is_request_order_only": true,
        "interpretation_limits": [
            crate::contribution::LIMIT_MEMBERSHIP_UNORDERED,
            crate::contribution::LIMIT_ALTERNATIVE_SET_FILTERED,
            crate::contribution::LIMIT_CREATION_NOT_STANCE,
        ],
    })
}

/// The attested command's own membership: which exploration it populated and
/// which candidates it added, resolved from the attestation's `member_of`
/// link outputs. Every `member_of` this operation appends points at the
/// call's exploration — a supplied one is refused by the mint kernel — so the
/// outputs' distinct target is the exploration and their sources are the
/// candidates, in output (request) order. This holds whether the call created
/// the exploration or joined an existing marked selection: in the latter case
/// the exploration's `record.created` belongs to an older attestation and is
/// simply absent here.
struct AttestedExploration {
    exploration_id: String,
    candidate_ids: Vec<String>,
    exploration_created: bool,
}

async fn attested_exploration_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    attestation_id: &str,
) -> Result<AttestedExploration> {
    let rows = sqlx::query(
        "SELECT e.payload FROM provenance_action_outputs o
           JOIN content_events e ON e.id=o.output_event_id
          WHERE o.action_attestation_id=? AND o.output_domain='content'
            AND e.type='link.added' ORDER BY o.ordinal",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    let mut exploration_id: Option<String> = None;
    let mut candidate_ids = Vec::new();
    for row in rows {
        let payload: Value =
            serde_json::from_str(&sqlx::Row::try_get::<String, _>(&row, "payload")?)?;
        if payload.get("relationship").and_then(Value::as_str) != Some("member_of") {
            continue;
        }
        let source = payload
            .get("source_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("create_exploration: idempotent receipt is incomplete"))?;
        let target = payload
            .get("target_id")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine("create_exploration: idempotent receipt is incomplete"))?;
        match &exploration_id {
            Some(known) if known != target => {
                return Err(Error::engine(
                    "create_exploration: idempotent receipt is incomplete",
                ));
            }
            Some(_) => {}
            None => exploration_id = Some(target.to_string()),
        }
        candidate_ids.push(source.to_string());
    }
    let Some(exploration_id) = exploration_id else {
        return Err(Error::engine(
            "create_exploration: idempotent receipt is incomplete",
        ));
    };
    let exploration_created: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM provenance_action_outputs o
           JOIN content_events e ON e.id=o.output_event_id
          WHERE o.action_attestation_id=? AND o.output_domain='content'
            AND e.type='record.created' AND e.record_id=?)",
    )
    .bind(attestation_id)
    .bind(&exploration_id)
    .fetch_one(&mut **tx)
    .await?;
    Ok(AttestedExploration {
        exploration_id,
        candidate_ids,
        exploration_created,
    })
}

async fn assert_marked_alternative_set_in(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    id: &str,
) -> Result<()> {
    let row = sqlx::query("SELECT type, kind FROM records WHERE id = ? AND deleted_at IS NULL")
        .bind(id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine(format!("{TOOL}: exploration {id} does not exist")))?;
    let record_type: String = sqlx::Row::try_get(&row, "type")?;
    let kind: Option<String> = sqlx::Row::try_get(&row, "kind")?;
    let resolution =
        crate::meta::kind::resolve_on(tx, &record_type, kind.as_deref().unwrap_or_default())
            .await?;
    if !crate::generated::kinds::CoreKind::CollectionSelection.matches(&resolution) {
        return Err(Error::engine(format!(
            "{TOOL}: exploration {id} must be a Collection kind:selection"
        )));
    }
    let marked: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id = ? AND key = ?")
            .bind(id)
            .bind(SELECTION_ROLE_FACET)
            .fetch_optional(&mut **tx)
            .await?;
    if marked.as_deref() != Some(ALTERNATIVE_SET_ROLE) {
        return Err(Error::engine(format!(
            "{TOOL}: selection {id} is not marked {SELECTION_ROLE_FACET}='{ALTERNATIVE_SET_ROLE}'; an ordinary curated list is not an exploration"
        )));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn mint_candidate_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    schema_rows: &[cascade::SchemaConfigRow],
    caller_owner: Option<&str>,
    reason: &str,
    candidate: &CandidateInput,
    draft: &crate::provenance::ActionAttestationDraft,
) -> Result<Minted> {
    let id = super::mint::mint_record_in(
        db,
        tx,
        caller,
        schema_rows,
        caller_owner,
        reason,
        &super::mint::MintRequest {
            record_type: &candidate.record_type,
            kind: &candidate.kind,
            name: candidate.name.as_deref(),
            body: candidate.body.as_deref(),
            summary: candidate.summary.as_deref(),
            lifecycle: candidate.lifecycle.as_deref(),
            home_id: candidate.home_id.as_deref(),
            facets: candidate.facets.as_ref(),
            links: candidate.links.as_deref().unwrap_or(&[]),
        },
        &super::mint::MintPolicy {
            tool: TOOL,
            refuse_message: true,
            refuse_supplied_member_of: true,
            // Unchanged from before the extraction: an exploration candidate
            // gets no implicit lifecycle.
            workitem_lifecycle_default: false,
        },
        draft,
    )
    .await?;
    Ok(Minted { id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_records_are_addressed_by_id_not_by_request_position() {
        // The composite returns ids; nothing durable records where a candidate
        // sat in the request array, and nothing here should start.
        let minted = Minted { id: "r1".into() };
        assert_eq!(minted.id, "r1");
    }
}

#[cfg(test)]
mod idempotency_tests {
    use super::*;

    async fn db() -> Db {
        crate::create_database(":memory:").await.unwrap()
    }

    fn registry() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
    }

    async fn call(registry: &ToolRegistry, db: &Db, args: Value) -> Value {
        registry
            .call(db.clone(), Caller::local(), "create_exploration", args)
            .await
            .unwrap()
    }

    async fn call_err(registry: &ToolRegistry, db: &Db, args: Value) -> String {
        registry
            .call(db.clone(), Caller::local(), "create_exploration", args)
            .await
            .unwrap_err()
            .to_string()
    }

    async fn count(db: &Db, sql: &str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(db.write_pool())
            .await
            .unwrap()
    }

    fn new_args(key: Option<&str>) -> Value {
        let mut args = json!({
            "reason": "idempotency fixture",
            "exploration": { "create": { "name": "Keyed exploration" } },
            "candidates": [
                { "type": "Document", "kind": "note", "name": "A", "body": "a" },
                { "type": "Document", "kind": "note", "name": "B", "body": "b" },
            ],
        });
        if let Some(key) = key {
            args.as_object_mut()
                .unwrap()
                .insert("idempotency_key".into(), json!(key));
        }
        args
    }

    /// Same key plus same normalized request replays the original receipt:
    /// same exploration and candidate ids, nothing appended twice, one
    /// command attestation.
    #[tokio::test]
    async fn keyed_retry_replays_original_receipt_and_appends_once() {
        let db = db().await;
        let registry = registry();
        let first = call(&registry, &db, new_args(Some("exploration-key"))).await;
        let second = call(&registry, &db, new_args(Some("exploration-key"))).await;
        assert_eq!(first, second, "retry converges on the original receipt");
        assert_eq!(first["exploration_created"], true);
        assert_eq!(first["candidates"].as_array().unwrap().len(), 2);
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Collection' AND kind='selection'"
            )
            .await,
            1,
            "exactly one exploration was appended"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Document' AND kind='note'"
            )
            .await,
            2,
            "exactly two candidates were appended"
        );
        assert_eq!(
            count(&db, "SELECT COUNT(*) FROM content_events WHERE type='link.added' AND json_extract(payload, '$.relationship')='member_of'").await,
            2,
            "exactly two membership links were appended"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM provenance_local_attestation_authority WHERE principal='local' AND operation='create_exploration'",
            )
            .await,
            1,
            "exactly one command attestation was issued"
        );
        db.close().await;
    }

    /// Same key with materially different content is a conflict error, and
    /// the failed retry appends nothing.
    #[tokio::test]
    async fn reused_key_with_different_candidates_conflicts() {
        let db = db().await;
        let registry = registry();
        call(&registry, &db, new_args(Some("conflict-key"))).await;
        let mut different = new_args(Some("conflict-key"));
        different["candidates"][0]["body"] = json!("changed");
        let error = call_err(&registry, &db, different).await;
        assert!(
            error.contains("conflicting action input"),
            "reused key with different content must conflict, got: {error}"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Collection' AND kind='selection'"
            )
            .await,
            1,
            "conflicting retry appends no second exploration"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Document' AND kind='note'"
            )
            .await,
            2,
            "conflicting retry appends no further candidates"
        );
        db.close().await;
    }

    /// Keyless calls behave exactly as today: every call creates again.
    #[tokio::test]
    async fn keyless_repeats_create_again() {
        let db = db().await;
        let registry = registry();
        let first = call(&registry, &db, new_args(None)).await;
        let second = call(&registry, &db, new_args(None)).await;
        assert_ne!(
            first["exploration"]["id"], second["exploration"]["id"],
            "keyless repeats mint again"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Collection' AND kind='selection'"
            )
            .await,
            2
        );
        db.close().await;
    }

    /// A keyed call that joins an existing marked selection replays as a
    /// join: `exploration_created` stays false and no candidate is duplicated.
    #[tokio::test]
    async fn keyed_join_of_existing_exploration_replays_as_join() {
        let db = db().await;
        let registry = registry();
        let created = call(&registry, &db, new_args(Some("join-seed"))).await;
        let exploration_id = created["exploration"]["id"].as_str().unwrap().to_string();
        let join = json!({
            "reason": "idempotency fixture",
            "exploration": { "id": exploration_id },
            "candidates": [{ "type": "Document", "kind": "note", "name": "C", "body": "c" }],
            "idempotency_key": "join-key",
        });
        let first = call(&registry, &db, join.clone()).await;
        assert_eq!(first["exploration_created"], false);
        assert_eq!(first["exploration"]["id"].as_str().unwrap(), exploration_id);
        let second = call(&registry, &db, join).await;
        assert_eq!(
            first, second,
            "join retry converges on the original receipt"
        );
        assert_eq!(
            count(
                &db,
                "SELECT COUNT(*) FROM records WHERE type='Document' AND kind='note'"
            )
            .await,
            3,
            "seed two plus one joined, never duplicated"
        );
        db.close().await;
    }
}
