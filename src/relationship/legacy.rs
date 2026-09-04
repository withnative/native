//! Sealed compatibility definition for the pre-v35 open-additive link graph.
//!
//! This module is deliberately crate-private. `manage_relationships` resolves
//! only the public manifest, while the v35 migration and `manage_links` adapter
//! are the only callers allowed to construct `legacy_link.v1` events.

use serde_json::{json, Map, Value};
use sqlx::Row;

use crate::{Error, Result};

use super::{
    AssertionCreatedV1, EndpointSemantics, LegacyHistoricalProvenance, LegacyLinkEnvelopeV1,
    RelationshipCreatedV1,
};

pub(crate) const LEGACY_LINK_DEFINITION_ID: &str = "legacy_link.v1";
pub(crate) const LEGACY_LINK_REDUCER_ID: &str = "legacy_link";
pub(crate) const LEGACY_SUPPORT_CLASS: &str = "source_authorised_support";
pub(crate) const LEGACY_CONTEST_CLASS: &str = "source_authorised_contest";

/// Engine-semantic links retain content-log ownership. This is intentionally a
/// closed list: adding a new internal producer requires an explicit replay
/// compatibility decision here, not a heuristic based on caller or timing.
const CONTENT_OWNED_RELATIONSHIPS: &[&str] = &[
    "acknowledges",
    "addressed_to",
    "authorizes",
    "derived_from",
    "instantiated_from",
    "member_of",
    "mentions",
    "part_of",
    "participates_in",
    "renders",
    "reply_to",
    "supersedes",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkOwnership {
    Content,
    Relationship,
}

/// One durable-semantics classifier used by migration, live projection,
/// rebuild and conformance. Message endpoints and federated link identities
/// remain content-owned independently of the relationship token.
pub(crate) fn classify(
    source_type: Option<&str>,
    target_type: Option<&str>,
    link_id: Option<&str>,
    relationship: &str,
) -> LinkOwnership {
    if source_type == Some("Message")
        || target_type == Some("Message")
        || link_id.is_some_and(|id| id.starts_with("lnk:fed:"))
        || CONTENT_OWNED_RELATIONSHIPS.contains(&relationship)
    {
        LinkOwnership::Content
    } else {
        LinkOwnership::Relationship
    }
}

pub(crate) fn validate_created_payload(payload: &RelationshipCreatedV1) -> Result<()> {
    let Some(legacy) = payload.legacy_link.as_ref() else {
        return Err(Error::engine(
            "legacy_link.v1 requires its sealed evidence envelope",
        ));
    };
    if payload.relationship_type != legacy.relationship_token
        || payload.endpoint_semantics != EndpointSemantics::Directed
        || payload.reducer_id != LEGACY_LINK_REDUCER_ID
        || payload.reducer_version != 1
        || legacy.schema_version != 1
        || legacy.relationship_token.trim().is_empty()
        || legacy.created_at.trim().is_empty()
        || payload.endpoints.len() != 2
        || payload.endpoints[0].role != "source"
        || payload.endpoints[1].role != "target"
        || payload
            .identity_qualifiers
            .get("relationship_token")
            .and_then(Value::as_str)
            != Some(legacy.relationship_token.as_str())
    {
        return Err(Error::engine("invalid sealed legacy_link.v1 payload"));
    }
    for (ordinal, fact) in legacy.source_facts.iter().enumerate() {
        if fact.ordinal != ordinal as u64
            || fact.content_event_id.trim().is_empty()
            || fact.occurred_at.trim().is_empty()
        {
            return Err(Error::engine(
                "legacy link source facts are not a closed ordered set",
            ));
        }
        if let LegacyHistoricalProvenance::Multiple {
            action_attestation_ids,
        } = &fact.historical_provenance
        {
            if action_attestation_ids.len() < 2
                || action_attestation_ids
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
            {
                return Err(Error::engine(
                    "multiple historical provenance references must be sorted and unique",
                ));
            }
        }
    }
    let expected = proposition_key(
        &payload.endpoints[0].portable_ref,
        &payload.endpoints[1].portable_ref,
        &legacy.relationship_token,
    );
    if payload.canonical_proposition_key != expected {
        return Err(Error::engine(
            "legacy link canonical proposition key mismatch",
        ));
    }
    Ok(())
}

pub(crate) fn validate_assertion_payload(payload: &AssertionCreatedV1) -> Result<()> {
    let expected_class = match payload.stance.as_str() {
        "support" => LEGACY_SUPPORT_CLASS,
        "contest" => LEGACY_CONTEST_CLASS,
        _ => return Err(Error::engine("legacy link assertion stance is invalid")),
    };
    if payload.origin_admission.admission_class() != expected_class
        || payload.origin_admission.authority_anchor().endpoint_role != "source"
        || payload.origin_admission.admission_rule() != "edit_source_view_target.v1"
    {
        return Err(Error::engine(
            "legacy link origin admission does not match the sealed compatibility route",
        ));
    }
    Ok(())
}

pub(crate) fn proposition_key(source_ref: &str, target_ref: &str, token: &str) -> String {
    crate::provenance::digest_json(&json!({
        "relationship_type_definition": LEGACY_LINK_DEFINITION_ID,
        "endpoints": [
            {"role":"source","portable_ref":source_ref},
            {"role":"target","portable_ref":target_ref}
        ],
        "qualifiers": {"relationship_token":token},
    }))
}

/// SHA-256-derived RFC4122 UUIDv4 shape. The origin participates in every
/// migration identity namespace so independently-created databases cannot
/// collide when later interchanged.
pub(crate) fn identity_qualifiers(token: &str) -> Map<String, Value> {
    Map::from_iter([("relationship_token".into(), Value::String(token.into()))])
}

pub(crate) fn migration_envelope(
    token: String,
    note: Option<String>,
    created_at: String,
    source_facts: Vec<super::LegacyLinkSourceFactV1>,
) -> LegacyLinkEnvelopeV1 {
    LegacyLinkEnvelopeV1 {
        schema_version: 1,
        relationship_token: token,
        note,
        created_at,
        source_facts,
    }
}

/// The only live constructor for the sealed definition. Endpoint
/// authorization/non-disclosure is completed by the `manage_links` handler in
/// the same transaction before entering this seam.
pub(crate) async fn mutate_from_manage_links_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &crate::mcp::registry::Caller,
    source_id: &str,
    target_id: &str,
    token: &str,
    note: Option<String>,
    add: bool,
) -> Result<Value> {
    let draft = crate::provenance::reserve_action_attestation()?;
    let (receipt, outputs) = mutate_with_reserved_attestation_in(
        tx,
        caller,
        source_id,
        target_id,
        token,
        note,
        add,
        "manage_links",
        &draft,
    )
    .await?;
    crate::provenance::issue_action_attestation_outputs_in(tx, draft, &outputs).await?;
    Ok(receipt)
}

/// Composite canvas entry point, for `manage_canvas.assert_connector` and
/// `manage_canvas.promote`.
///
/// Same contract as [`mutate_from_create_record_in`]: the caller reserves one
/// action identity for the whole command and finalizes it over every content
/// and relationship output immediately before commit, so the link the canvas
/// asserts and the batch that records the assertion share one attestation and
/// `inspect_action_attestation` can answer "which canvas gesture asserted
/// this link".
pub(crate) async fn mutate_from_canvas_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &crate::mcp::registry::Caller,
    source_id: &str,
    target_id: &str,
    token: &str,
    note: Option<String>,
    draft: &crate::provenance::ActionAttestationDraft,
) -> Result<Value> {
    let (receipt, _) = mutate_with_reserved_attestation_in(
        tx,
        caller,
        source_id,
        target_id,
        token,
        note,
        true,
        "manage_canvas",
        draft,
    )
    .await?;
    Ok(receipt)
}

/// Composite create_record entry point. The caller reserves one action
/// identity for the whole command and finalizes it over every content and
/// relationship output immediately before commit.
pub(crate) async fn mutate_from_create_record_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &crate::mcp::registry::Caller,
    source_id: &str,
    target_id: &str,
    token: &str,
    note: Option<String>,
    draft: &crate::provenance::ActionAttestationDraft,
) -> Result<Value> {
    let (receipt, _) = mutate_with_reserved_attestation_in(
        tx,
        caller,
        source_id,
        target_id,
        token,
        note,
        true,
        "create_record",
        draft,
    )
    .await?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
async fn mutate_with_reserved_attestation_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &crate::mcp::registry::Caller,
    source_id: &str,
    target_id: &str,
    token: &str,
    note: Option<String>,
    add: bool,
    operation: &str,
    draft: &crate::provenance::ActionAttestationDraft,
) -> Result<(Value, Vec<crate::provenance::ActionOutput>)> {
    let origin: String =
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?;
    let source_ref = crate::identity::encode_native_record(&origin, source_id)?;
    let target_ref = crate::identity::encode_native_record(&origin, target_id)?;
    let proposition = proposition_key(&source_ref, &target_ref, token);
    let existing = sqlx::query(
        "SELECT r.relationship_id,r.status,r.created_event_issuer_origin_db_id,r.created_event_id,
                e.effective_state,e.epistemic_state
           FROM relationships r LEFT JOIN effective_relationships e
             ON e.relationship_origin_db_id=r.relationship_origin_db_id
            AND e.relationship_id=r.relationship_id
          WHERE r.relationship_origin_db_id=? AND r.type_definition_id=?
            AND r.canonical_proposition_key=?",
    )
    .bind(&origin)
    .bind(LEGACY_LINK_DEFINITION_ID)
    .bind(&proposition)
    .fetch_optional(&mut **tx)
    .await?;
    if !add {
        let Some(row) = existing.as_ref() else {
            return Err(Error::engine(format!(
                "cannot remove link: no '{token}' link from {source_id} to {target_id}"
            )));
        };
        if row
            .try_get::<Option<String>, _>("effective_state")?
            .as_deref()
            != Some("active")
        {
            return Err(Error::engine(
                "manage_links: compatibility state is inactive or causally unresolved; use manage_relationships to inspect the assertion frontier",
            ));
        }
    }
    let attestation_id = draft.id().to_string();
    let stance = if add { "support" } else { "contest" };
    let class = if add {
        LEGACY_SUPPORT_CLASS
    } else {
        LEGACY_CONTEST_CLASS
    };
    let auth_digest = crate::provenance::digest_json(&json!({
        "schema_version":1,"principal":caller.credential(),"operation":operation,
        "relationship_type_definition":LEGACY_LINK_DEFINITION_ID,"admission_class":class,
        "authority_anchor":{"endpoint_role":"source","endpoint_ref":source_ref},
        "admission_rule":"edit_source_view_target.v1"
    }));
    let admission = super::OriginAdmissionV1::from_legacy_authorization(
        class,
        source_ref.clone(),
        auth_digest,
        attestation_id.clone(),
    );
    let now = crate::store::now_iso();
    let (relationship_id, assertion_id, output_ids) = if let Some(row) = existing {
        if row.try_get::<String, _>("status")? != "active" {
            return Err(Error::engine(
                "manage_links: compatibility relationship is retired; use manage_relationships",
            ));
        }
        let relationship_id: String = row.try_get("relationship_id")?;
        let parents = causal_frontier_parents_in(tx, &origin, &relationship_id).await?;
        let assertion_id = uuid::Uuid::new_v4().to_string();
        let event_id = uuid::Uuid::new_v4().to_string();
        let assertion = AssertionCreatedV1 {
            schema_version: 1,
            relationship: super::RelationshipCoordinate {
                relationship_origin_db_id: origin.clone(),
                relationship_id: relationship_id.clone(),
                relationship_revision: 1,
            },
            relationship_created_event: super::RelationshipEventCoordinate {
                issuer_origin_db_id: row.try_get("created_event_issuer_origin_db_id")?,
                event_id: row.try_get("created_event_id")?,
            },
            stance: stance.into(),
            semantic_claimant: caller.credential().into(),
            on_behalf_of: None,
            rationale: Some(if add {
                format!("{operation} compatibility add")
            } else {
                format!("{operation} compatibility remove")
            }),
            valid_from: None,
            valid_until: None,
            causal_parents: parents,
            origin_admission: admission,
            authoring_action_attestation_id: attestation_id.clone(),
        };
        let spec = super::RelationshipEventSpec {
            event_id: event_id.clone(),
            stream_id: assertion_id.clone(),
            expected_stream_version: 0,
            relationship: assertion.relationship.clone(),
            payload: super::RelationshipEventPayload::AssertionCreated(assertion),
            actor: caller.actor().into(),
            issuer_origin_db_id: origin.clone(),
            occurred_at: now.clone(),
            ingested_at: now.clone(),
        };
        super::append_relationship_event_in(tx, &spec).await?;
        (relationship_id, assertion_id, vec![event_id])
    } else {
        let source = sqlx::query("SELECT type,kind FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(source_id)
            .fetch_one(&mut **tx)
            .await?;
        let target = sqlx::query("SELECT type,kind FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(target_id)
            .fetch_one(&mut **tx)
            .await?;
        let endpoints = vec![
            super::RelationshipEndpoint {
                role: "source".into(),
                portable_ref: source_ref.clone(),
                record_type: Some(source.try_get("type")?),
                record_kind: source.try_get("kind")?,
                record_id: Some(source_id.into()),
            },
            super::RelationshipEndpoint {
                role: "target".into(),
                portable_ref: target_ref.clone(),
                record_type: Some(target.try_get("type")?),
                record_kind: target.try_get("kind")?,
                record_id: Some(target_id.into()),
            },
        ];
        let created = RelationshipCreatedV1 {
            schema_version: 1,
            relationship_revision: 1,
            relationship_type: token.into(),
            type_definition_id: LEGACY_LINK_DEFINITION_ID.into(),
            endpoint_semantics: EndpointSemantics::Directed,
            endpoints,
            identity_qualifiers: identity_qualifiers(token),
            canonical_proposition_key: proposition,
            reducer_id: LEGACY_LINK_REDUCER_ID.into(),
            reducer_version: 1,
            legacy_link: Some(migration_envelope(
                token.into(),
                note,
                now.clone(),
                Vec::new(),
            )),
        };
        let assertion = AssertionCreatedV1 {
            schema_version: 1,
            relationship: super::RelationshipCoordinate {
                relationship_origin_db_id: origin.clone(),
                relationship_id: uuid::Uuid::new_v4().to_string(),
                relationship_revision: 1,
            },
            relationship_created_event: super::RelationshipEventCoordinate {
                issuer_origin_db_id: origin.clone(),
                event_id: uuid::Uuid::new_v4().to_string(),
            },
            stance: stance.into(),
            semantic_claimant: caller.credential().into(),
            on_behalf_of: None,
            rationale: Some(format!("{operation} compatibility add")),
            valid_from: None,
            valid_until: None,
            causal_parents: Vec::new(),
            origin_admission: admission,
            authoring_action_attestation_id: attestation_id.clone(),
        };
        let command = super::prepare_relationship_with_assertion(
            &origin,
            caller.actor(),
            &now,
            &now,
            created,
            assertion,
        )?;
        let relationship_id = command.relationship_event.stream_id.clone();
        let assertion_id = command.assertion_event.stream_id.clone();
        let output_ids = vec![
            command.relationship_event.event_id.clone(),
            command.assertion_event.event_id.clone(),
        ];
        super::create_relationship_with_assertion_in(tx, &command).await?;
        (relationship_id, assertion_id, output_ids)
    };
    let outputs = output_ids
        .iter()
        .cloned()
        .map(crate::provenance::ActionOutput::relationship)
        .collect::<Vec<_>>();
    Ok((
        json!({
            "status":if add{"added"}else{"removed"},"source_id":source_id,"target_id":target_id,
            "relationship":token,"relationship_origin_db_id":origin,"relationship_id":relationship_id,
            "assertion_id":assertion_id,
            "action_attestation_id":attestation_id,
            "output_events":output_ids.into_iter().map(|event_id| json!({"domain":"relationship","issuer_origin_db_id":origin,"event_id":event_id})).collect::<Vec<_>>()
        }),
        outputs,
    ))
}

async fn causal_frontier_parents_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    origin: &str,
    relationship_id: &str,
) -> Result<Vec<super::CausalAssertionParent>> {
    let rows = sqlx::query(
        "SELECT issuer_origin_db_id,assertion_id,stream_version,last_event_issuer_origin_db_id,last_event_id
           FROM relationship_assertion_heads
          WHERE relationship_origin_db_id=? AND relationship_id=? AND state='active'
          ORDER BY issuer_origin_db_id,assertion_id",
    ).bind(origin).bind(relationship_id).fetch_all(&mut **tx).await?;
    rows.into_iter()
        .map(|row| {
            Ok(super::CausalAssertionParent {
                assertion_issuer_origin_db_id: row.try_get("issuer_origin_db_id")?,
                assertion_id: row.try_get("assertion_id")?,
                head_event_issuer_origin_db_id: row.try_get("last_event_issuer_origin_db_id")?,
                head_event_id: row.try_get("last_event_id")?,
                head_stream_version: u64::try_from(row.try_get::<i64, _>("stream_version")?)
                    .map_err(|_| Error::engine("invalid legacy assertion stream version"))?,
            })
        })
        .collect()
}
