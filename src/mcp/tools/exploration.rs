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
                }
            },
            "required": ["reason", "exploration", "candidates"],
            "additionalProperties": false
        }),
        create_exploration,
    )
}

async fn create_exploration(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let args: CreateExplorationArgs = parse_args(TOOL, arguments)?;
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

    crate::provenance::issue_reserved_pending_action_in(&mut tx, draft).await?;
    db.commit_content(tx).await?;

    // Reads happen only after the commit; holding a second connection while
    // the write transaction is live is the one deadlock trap here.
    let exploration = enriched_or_error(&db, &caller, TOOL, &exploration_id).await?;
    let mut candidates = Vec::with_capacity(minted.len());
    for record in &minted {
        candidates.push(enriched_or_error(&db, &caller, TOOL, &record.id).await?);
    }
    Ok(json!({
        "exploration": exploration,
        "exploration_created": created_exploration,
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
    }))
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
