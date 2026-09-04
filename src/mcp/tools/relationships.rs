//! Governed relationship assertions. Unlike `manage_links`, this surface writes
//! independently versioned relationship/assertion streams and never grants a
//! record capability.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{json, Map, Value};
use sqlx::{Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::authorization::Capability;
use crate::mcp::registry::{Caller, ToolRegistry};
use crate::mcp::ToolKind;
use crate::provenance::{ActionOutput, InspectionDetail};
use crate::relationship::{
    AssertionCreatedV1, AssertionEvidenceAddedV1, AssertionStateChangedV1, AuthorityAnchorRule,
    CausalAssertionParent, EndpointSemantics, OriginAdmissionV1, PropositionEndpoint,
    RelationshipCoordinate, RelationshipCreatedV1, RelationshipEndpoint,
    RelationshipEventCoordinate, RelationshipEventPayload, RelationshipEventSpec,
    RelationshipTypeDefinition,
};
use crate::{Db, Error, Result};

use super::{can_record_in, parse_args, require_record_in};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointInput {
    role: String,
    record_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CausalParentInput {
    assertion_issuer_origin_db_id: String,
    assertion_id: String,
    head_event_issuer_origin_db_id: String,
    head_event_id: String,
    head_stream_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
enum ManageRelationshipsArgs {
    Assert {
        relationship_type: String,
        endpoints: Vec<EndpointInput>,
        #[serde(default)]
        identity_qualifiers: Map<String, Value>,
        #[serde(default)]
        rationale: Option<String>,
        #[serde(default)]
        valid_from: Option<String>,
        #[serde(default)]
        valid_until: Option<String>,
        #[serde(default)]
        causal_parents: Vec<CausalParentInput>,
        #[serde(default)]
        on_behalf_of: Option<String>,
        idempotency_key: String,
    },
    Contest {
        relationship_origin_db_id: String,
        relationship_id: String,
        #[serde(default)]
        rationale: Option<String>,
        #[serde(default)]
        causal_parents: Vec<CausalParentInput>,
        #[serde(default)]
        on_behalf_of: Option<String>,
        idempotency_key: String,
    },
    AddEvidence {
        assertion_issuer_origin_db_id: String,
        assertion_id: String,
        evidence_id: String,
        reason: String,
        idempotency_key: String,
    },
    Retract {
        assertion_issuer_origin_db_id: String,
        assertion_id: String,
        reason: String,
        idempotency_key: String,
    },
    Read {
        relationship_origin_db_id: String,
        relationship_id: String,
    },
    Why {
        relationship_origin_db_id: String,
        relationship_id: String,
    },
    Find {
        #[serde(default)]
        endpoint_record_id: Option<String>,
        #[serde(default)]
        endpoint_current_person: bool,
        #[serde(default)]
        relationship_type: Option<String>,
        #[serde(default)]
        endpoint_role: Option<String>,
        #[serde(default)]
        effective_state: Option<String>,
        #[serde(default)]
        epistemic_state: Option<String>,
        #[serde(default)]
        counterpart_lifecycle: Option<String>,
        #[serde(default)]
        limit: Option<i64>,
        #[serde(default)]
        offset: Option<i64>,
    },
}

#[derive(Clone)]
struct ResolvedRelationship {
    coordinate: RelationshipCoordinate,
    created_event: RelationshipEventCoordinate,
    definition: RelationshipTypeDefinition,
    created: RelationshipCreatedV1,
}

async fn manage_relationships(db: Db, caller: Caller, arguments: Value) -> Result<Value> {
    let parsed = parse_args("manage_relationships", arguments.clone())?;
    match parsed {
        ManageRelationshipsArgs::Assert {
            relationship_type,
            endpoints,
            identity_qualifiers,
            rationale,
            valid_from,
            valid_until,
            causal_parents,
            on_behalf_of,
            idempotency_key,
        } => {
            require_idempotency_key(&idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let result = async {
                let definition = definition(&relationship_type)?;
                let created = resolve_new_relationship_in(
                    &mut tx,
                    &caller,
                    &definition,
                    endpoints,
                    identity_qualifiers,
                )
                .await?;
                let anchor =
                    authority_anchor_in(&mut tx, &caller, &definition, &created, "support").await?;
                let existing = find_relationship_in(&mut tx, &created).await?;
                if let Some(attestation_id) =
                    crate::provenance::lookup_authorized_command_attestation_in(
                        &mut tx,
                        caller.credential(),
                        "manage_relationships",
                        &arguments,
                        caller.intent(),
                    )
                    .await?
                {
                    let response = reconstruct_retry_in(&mut tx, &attestation_id, "assert").await?;
                    crate::provenance::note_replayed_action_attestation(attestation_id);
                    return Ok((response, false));
                }
                let draft = crate::provenance::reserve_action_attestation()?;
                let admission_class = admission_class(&definition, "support")?;
                let admission = crate::provenance::authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &created,
                    "support",
                    &admission_class.id,
                    &anchor.role,
                    &anchor.portable_ref,
                )
                .await?;
                let origin = local_origin_in(&mut tx).await?;
                let now = crate::store::now_iso();
                let assertion = assertion_created(
                    &caller,
                    "support",
                    on_behalf_of,
                    rationale,
                    valid_from,
                    valid_until,
                    causal_parents,
                    OriginAdmissionV1::from_local_authorization(admission),
                    draft.id(),
                );
                let (relationship_id, assertion_id, outputs) = if let Some(existing) = existing {
                    let spec =
                        assertion_genesis_spec(&origin, &caller, &now, &existing, assertion)?;
                    let assertion_id = spec.stream_id.clone();
                    let relationship_id = existing.coordinate.relationship_id.clone();
                    let event_id = spec.event_id.clone();
                    crate::relationship::append_relationship_event_in(&mut tx, &spec).await?;
                    (
                        relationship_id,
                        assertion_id,
                        vec![ActionOutput::relationship(event_id)],
                    )
                } else {
                    let command = crate::relationship::prepare_relationship_with_assertion(
                        &origin,
                        caller.actor(),
                        &now,
                        &now,
                        created,
                        assertion,
                    )?;
                    let relationship_id = command.relationship_event.stream_id.clone();
                    let assertion_id = command.assertion_event.stream_id.clone();
                    let outputs = vec![
                        ActionOutput::relationship(command.relationship_event.event_id.clone()),
                        ActionOutput::relationship(command.assertion_event.event_id.clone()),
                    ];
                    crate::relationship::create_relationship_with_assertion_in(&mut tx, &command)
                        .await?;
                    (relationship_id, assertion_id, outputs)
                };
                let output_events = outputs
                    .iter()
                    .map(|output| (origin.as_str(), output.event_id.as_str()))
                    .collect::<Vec<_>>();
                crate::provenance::issue_action_attestation_outputs_in(&mut tx, draft, &outputs)
                    .await?;
                Ok((
                    relationship_receipt(
                        "asserted",
                        &origin,
                        &relationship_id,
                        &assertion_id,
                        1,
                        &output_events,
                    ),
                    true,
                ))
            }
            .await;
            finish_write(&db, tx, result).await
        }
        ManageRelationshipsArgs::Contest {
            relationship_origin_db_id,
            relationship_id,
            rationale,
            causal_parents,
            on_behalf_of,
            idempotency_key,
        } => {
            require_idempotency_key(&idempotency_key)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let result = async {
                let relationship = load_relationship_in(
                    &mut tx,
                    &caller,
                    &relationship_origin_db_id,
                    &relationship_id,
                )
                .await?;
                let origin = local_origin_in(&mut tx).await?;
                if relationship.coordinate.relationship_origin_db_id != origin {
                    return Err(opaque_relationship());
                }
                let anchor = authority_anchor_in(
                    &mut tx,
                    &caller,
                    &relationship.definition,
                    &relationship.created,
                    "contest",
                )
                .await?;
                if let Some(attestation_id) =
                    crate::provenance::lookup_authorized_command_attestation_in(
                        &mut tx,
                        caller.credential(),
                        "manage_relationships",
                        &arguments,
                        caller.intent(),
                    )
                    .await?
                {
                    let response =
                        reconstruct_retry_in(&mut tx, &attestation_id, "contest").await?;
                    crate::provenance::note_replayed_action_attestation(attestation_id);
                    return Ok((response, false));
                }
                let draft = crate::provenance::reserve_action_attestation()?;
                let class = admission_class(&relationship.definition, "contest")?;
                let admission = crate::provenance::authorize_local_origin_admission_in(
                    &mut tx,
                    &caller,
                    &draft,
                    &relationship.created,
                    "contest",
                    &class.id,
                    &anchor.role,
                    &anchor.portable_ref,
                )
                .await?;
                let now = crate::store::now_iso();
                let assertion = assertion_created(
                    &caller,
                    "contest",
                    on_behalf_of,
                    rationale,
                    None,
                    None,
                    causal_parents,
                    OriginAdmissionV1::from_local_authorization(admission),
                    draft.id(),
                );
                let spec =
                    assertion_genesis_spec(&origin, &caller, &now, &relationship, assertion)?;
                let assertion_id = spec.stream_id.clone();
                let event_id = spec.event_id.clone();
                let assertion_stream_version = spec.stream_version()?;
                crate::relationship::append_relationship_event_in(&mut tx, &spec).await?;
                crate::provenance::issue_action_attestation_outputs_in(
                    &mut tx,
                    draft,
                    &[ActionOutput::relationship(event_id.clone())],
                )
                .await?;
                Ok((
                    relationship_receipt(
                        "contested",
                        &origin,
                        &relationship.coordinate.relationship_id,
                        &assertion_id,
                        assertion_stream_version,
                        &[(origin.as_str(), event_id.as_str())],
                    ),
                    true,
                ))
            }
            .await;
            finish_write(&db, tx, result).await
        }
        ManageRelationshipsArgs::AddEvidence {
            assertion_issuer_origin_db_id,
            assertion_id,
            evidence_id,
            reason,
            idempotency_key,
        } => {
            require_idempotency_key(&idempotency_key)?;
            require_nonblank("reason", &reason)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let result = async {
                let assertion = authorize_assertion_mutation_in(
                    &mut tx,
                    &caller,
                    &assertion_issuer_origin_db_id,
                    &assertion_id,
                )
                .await?;
                require_record_in(
                    &mut tx,
                    &caller,
                    "manage_relationships",
                    &evidence_id,
                    Capability::View,
                )
                .await?;
                if let Some(attestation_id) =
                    crate::provenance::lookup_authorized_command_attestation_in(
                        &mut tx,
                        caller.credential(),
                        "manage_relationships",
                        &arguments,
                        caller.intent(),
                    )
                    .await?
                {
                    let response =
                        reconstruct_retry_in(&mut tx, &attestation_id, "add_evidence").await?;
                    crate::provenance::note_replayed_action_attestation(attestation_id);
                    return Ok((response, false));
                }
                if !assertion.active {
                    return Err(opaque_relationship());
                }
                let draft = crate::provenance::reserve_action_attestation()?;
                let origin = local_origin_in(&mut tx).await?;
                let evidence_ref = crate::identity::encode_native_record(&origin, &evidence_id)?;
                let spec = next_assertion_event(
                    &caller,
                    &origin,
                    &assertion,
                    RelationshipEventPayload::AssertionEvidenceAdded(AssertionEvidenceAddedV1 {
                        schema_version: 1,
                        evidence_ref,
                        reason,
                    }),
                )?;
                let event_id = spec.event_id.clone();
                let assertion_stream_version = spec.stream_version()?;
                crate::relationship::append_relationship_event_in(&mut tx, &spec).await?;
                crate::provenance::issue_action_attestation_outputs_in(
                    &mut tx,
                    draft,
                    &[ActionOutput::relationship(event_id.clone())],
                )
                .await?;
                let mut receipt = relationship_receipt(
                    "evidence_added",
                    &origin,
                    &assertion.coordinate.relationship_id,
                    &assertion.assertion_id,
                    assertion_stream_version,
                    &[(origin.as_str(), event_id.as_str())],
                );
                receipt["evidence_id"] = json!(evidence_id);
                Ok((receipt, true))
            }
            .await;
            finish_write(&db, tx, result).await
        }
        ManageRelationshipsArgs::Retract {
            assertion_issuer_origin_db_id,
            assertion_id,
            reason,
            idempotency_key,
        } => {
            require_idempotency_key(&idempotency_key)?;
            require_nonblank("reason", &reason)?;
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let result = async {
                let assertion = authorize_assertion_mutation_in(
                    &mut tx,
                    &caller,
                    &assertion_issuer_origin_db_id,
                    &assertion_id,
                )
                .await?;
                if let Some(attestation_id) =
                    crate::provenance::lookup_authorized_command_attestation_in(
                        &mut tx,
                        caller.credential(),
                        "manage_relationships",
                        &arguments,
                        caller.intent(),
                    )
                    .await?
                {
                    let response =
                        reconstruct_retry_in(&mut tx, &attestation_id, "retract").await?;
                    crate::provenance::note_replayed_action_attestation(attestation_id);
                    return Ok((response, false));
                }
                if !assertion.active {
                    return Err(opaque_relationship());
                }
                let draft = crate::provenance::reserve_action_attestation()?;
                let origin = local_origin_in(&mut tx).await?;
                let spec = next_assertion_event(
                    &caller,
                    &origin,
                    &assertion,
                    RelationshipEventPayload::AssertionRetracted(AssertionStateChangedV1 {
                        schema_version: 1,
                        reason,
                    }),
                )?;
                let event_id = spec.event_id.clone();
                let assertion_stream_version = spec.stream_version()?;
                crate::relationship::append_relationship_event_in(&mut tx, &spec).await?;
                crate::provenance::issue_action_attestation_outputs_in(
                    &mut tx,
                    draft,
                    &[ActionOutput::relationship(event_id.clone())],
                )
                .await?;
                Ok((
                    relationship_receipt(
                        "retracted",
                        &origin,
                        &assertion.coordinate.relationship_id,
                        &assertion.assertion_id,
                        assertion_stream_version,
                        &[(origin.as_str(), event_id.as_str())],
                    ),
                    true,
                ))
            }
            .await;
            finish_write(&db, tx, result).await
        }
        ManageRelationshipsArgs::Read {
            relationship_origin_db_id,
            relationship_id,
        } => {
            read_relationship(
                &db,
                &caller,
                &relationship_origin_db_id,
                &relationship_id,
                false,
            )
            .await
        }
        ManageRelationshipsArgs::Why {
            relationship_origin_db_id,
            relationship_id,
        } => {
            read_relationship(
                &db,
                &caller,
                &relationship_origin_db_id,
                &relationship_id,
                true,
            )
            .await
        }
        ManageRelationshipsArgs::Find {
            endpoint_record_id,
            endpoint_current_person,
            relationship_type,
            endpoint_role,
            effective_state,
            epistemic_state,
            counterpart_lifecycle,
            limit,
            offset,
        } => {
            find_relationships(
                &db,
                &caller,
                FindArgs {
                    endpoint_record_id,
                    endpoint_current_person,
                    relationship_type,
                    endpoint_role,
                    effective_state,
                    epistemic_state,
                    counterpart_lifecycle,
                    limit,
                    offset,
                },
            )
            .await
        }
    }
}

async fn finish_write(
    db: &Db,
    tx: Transaction<'static, Sqlite>,
    result: Result<(Value, bool)>,
) -> Result<Value> {
    match result {
        Ok((value, true)) => {
            db.commit_content(tx).await?;
            Ok(value)
        }
        Ok((value, false)) => {
            tx.rollback().await?;
            Ok(value)
        }
        Err(error) => {
            let _ = tx.rollback().await;
            Err(error)
        }
    }
}

fn require_idempotency_key(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 200 {
        return Err(Error::engine(
            "manage_relationships: idempotency_key must be 1..200 characters",
        ));
    }
    Ok(())
}

fn require_nonblank(field: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(Error::engine(format!(
            "manage_relationships: {field} must not be blank"
        )));
    }
    Ok(())
}

fn opaque_relationship() -> Error {
    Error::engine("manage_relationships: relationship does not exist")
}

fn definition(relationship_type: &str) -> Result<RelationshipTypeDefinition> {
    crate::relationship::core_relationship_type_manifest()?
        .relationship_types
        .into_iter()
        .find(|definition| definition.relationship_type == relationship_type)
        .ok_or_else(|| Error::engine("manage_relationships: relationship type is not governed"))
}

fn admission_class<'a>(
    definition: &'a RelationshipTypeDefinition,
    stance: &str,
) -> Result<&'a crate::relationship::AssertionAdmissionClass> {
    let matches = definition
        .assertion_admission_classes
        .iter()
        .filter(|class| class.stance == stance)
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err(Error::engine(format!(
            "manage_relationships: {stance} is not governed for this relationship type"
        )));
    }
    Ok(matches[0])
}

async fn local_origin_in(tx: &mut Transaction<'_, Sqlite>) -> Result<String> {
    Ok(
        sqlx::query_scalar("SELECT origin_db_id FROM database_identity WHERE singleton=1")
            .fetch_one(&mut **tx)
            .await?,
    )
}

async fn resolve_new_relationship_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    definition: &RelationshipTypeDefinition,
    endpoints: Vec<EndpointInput>,
    identity_qualifiers: Map<String, Value>,
) -> Result<RelationshipCreatedV1> {
    let origin = local_origin_in(tx).await?;
    // Complete endpoint non-disclosure before consulting any endpoint's
    // semantic metadata. A later type/kind rejection must never reveal that a
    // different supplied endpoint was hidden or absent.
    for endpoint in &endpoints {
        require_nonblank("endpoint role", &endpoint.role)?;
        require_record_in(
            tx,
            caller,
            "manage_relationships",
            &endpoint.record_id,
            Capability::View,
        )
        .await
        .map_err(|_| opaque_relationship())?;
    }
    let mut resolved = Vec::with_capacity(endpoints.len());
    for endpoint in endpoints {
        let row = sqlx::query("SELECT type,kind FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&endpoint.record_id)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or_else(opaque_relationship)?;
        resolved.push(RelationshipEndpoint {
            role: endpoint.role,
            portable_ref: crate::identity::encode_native_record(&origin, &endpoint.record_id)?,
            record_type: Some(row.try_get("type")?),
            record_kind: row.try_get("kind")?,
            record_id: Some(endpoint.record_id),
        });
    }
    if definition.endpoint_semantics == EndpointSemantics::Symmetric {
        resolved.sort_by(|left, right| left.portable_ref.cmp(&right.portable_ref));
    } else {
        resolved.sort_by_key(|endpoint| {
            definition
                .endpoints
                .iter()
                .position(|rule| rule.role == endpoint.role)
                .unwrap_or(usize::MAX)
        });
    }
    let proposition_endpoints = resolved
        .iter()
        .map(RelationshipEndpoint::proposition_endpoint)
        .collect::<Vec<PropositionEndpoint>>();
    let qualifiers = identity_qualifiers
        .clone()
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let canonical_proposition_key =
        definition.canonical_proposition_key(&proposition_endpoints, &qualifiers)?;
    let created = RelationshipCreatedV1 {
        schema_version: 1,
        relationship_revision: 1,
        relationship_type: definition.relationship_type.clone(),
        type_definition_id: definition.id.clone(),
        endpoint_semantics: definition.endpoint_semantics,
        endpoints: resolved,
        identity_qualifiers,
        canonical_proposition_key,
        reducer_id: definition.reducer.id.clone(),
        reducer_version: definition.reducer.version,
        legacy_link: None,
    };
    RelationshipEventPayload::RelationshipCreated(created.clone()).validate()?;
    Ok(created)
}

async fn find_relationship_in(
    tx: &mut Transaction<'_, Sqlite>,
    created: &RelationshipCreatedV1,
) -> Result<Option<ResolvedRelationship>> {
    let origin = local_origin_in(tx).await?;
    let row = sqlx::query(
        "SELECT relationship_id,created_event_issuer_origin_db_id,created_event_id
           FROM relationships
          WHERE relationship_origin_db_id=? AND type_definition_id=?
            AND canonical_proposition_key=? AND status='active'",
    )
    .bind(&origin)
    .bind(&created.type_definition_id)
    .bind(&created.canonical_proposition_key)
    .fetch_optional(&mut **tx)
    .await?;
    row.map(|row| {
        Ok(ResolvedRelationship {
            coordinate: RelationshipCoordinate {
                relationship_origin_db_id: origin,
                relationship_id: row.try_get("relationship_id")?,
                relationship_revision: 1,
            },
            created_event: RelationshipEventCoordinate {
                issuer_origin_db_id: row.try_get("created_event_issuer_origin_db_id")?,
                event_id: row.try_get("created_event_id")?,
            },
            definition: definition(&created.relationship_type)?,
            created: created.clone(),
        })
    })
    .transpose()
}

async fn load_relationship_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    origin: &str,
    relationship_id: &str,
) -> Result<ResolvedRelationship> {
    // Resolve and authorize every endpoint before consulting proposition
    // metadata. This keeps unknown/corrupt definitions and aggregate state
    // from becoming a relationship-existence oracle.
    let endpoints = load_endpoints_and_authorize_in(tx, caller, origin, relationship_id).await?;
    let row = sqlx::query(
        "SELECT relationship_type,created_event_issuer_origin_db_id,created_event_id,status,
                relationship_revision,type_definition_id,endpoint_semantics,identity_qualifiers,
                canonical_proposition_key,reducer_id,reducer_version
           FROM relationships WHERE relationship_origin_db_id=? AND relationship_id=?",
    )
    .bind(origin)
    .bind(relationship_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(opaque_relationship)?;
    if row.try_get::<String, _>("status")? != "active" {
        return Err(opaque_relationship());
    }
    let relationship_type: String = row.try_get("relationship_type")?;
    let definition = definition(&relationship_type)?;
    Ok(ResolvedRelationship {
        coordinate: RelationshipCoordinate {
            relationship_origin_db_id: origin.into(),
            relationship_id: relationship_id.into(),
            relationship_revision: u64::try_from(row.try_get::<i64, _>("relationship_revision")?)
                .map_err(|_| opaque_relationship())?,
        },
        created_event: RelationshipEventCoordinate {
            issuer_origin_db_id: row.try_get("created_event_issuer_origin_db_id")?,
            event_id: row.try_get("created_event_id")?,
        },
        definition,
        created: RelationshipCreatedV1 {
            schema_version: 1,
            relationship_revision: u64::try_from(row.try_get::<i64, _>("relationship_revision")?)
                .map_err(|_| opaque_relationship())?,
            relationship_type,
            type_definition_id: row.try_get("type_definition_id")?,
            endpoint_semantics: match row.try_get::<String, _>("endpoint_semantics")?.as_str() {
                "directed" => EndpointSemantics::Directed,
                "symmetric" => EndpointSemantics::Symmetric,
                _ => return Err(opaque_relationship()),
            },
            endpoints,
            identity_qualifiers: serde_json::from_str(
                &row.try_get::<String, _>("identity_qualifiers")?,
            )?,
            canonical_proposition_key: row.try_get("canonical_proposition_key")?,
            reducer_id: row.try_get("reducer_id")?,
            reducer_version: u64::try_from(row.try_get::<i64, _>("reducer_version")?)
                .map_err(|_| opaque_relationship())?,
            legacy_link: None,
        },
    })
}

async fn load_endpoints_and_authorize_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    origin: &str,
    relationship_id: &str,
) -> Result<Vec<RelationshipEndpoint>> {
    let rows = sqlx::query(
        "SELECT role,portable_ref,record_type,record_kind,record_id
           FROM relationship_endpoints
          WHERE relationship_origin_db_id=? AND relationship_id=? ORDER BY ordinal",
    )
    .bind(origin)
    .bind(relationship_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Err(opaque_relationship());
    }
    let mut endpoints = Vec::with_capacity(rows.len());
    for row in rows {
        let record_id: Option<String> = row.try_get("record_id")?;
        let Some(record_id) = record_id else {
            return Err(opaque_relationship());
        };
        require_record_in(
            tx,
            caller,
            "manage_relationships",
            &record_id,
            Capability::View,
        )
        .await
        .map_err(|_| opaque_relationship())?;
        endpoints.push(RelationshipEndpoint {
            role: row.try_get("role")?,
            portable_ref: row.try_get("portable_ref")?,
            record_type: row.try_get("record_type")?,
            record_kind: row.try_get("record_kind")?,
            record_id: Some(record_id),
        });
    }
    Ok(endpoints)
}

async fn authority_anchor_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    definition: &RelationshipTypeDefinition,
    created: &RelationshipCreatedV1,
    stance: &str,
) -> Result<RelationshipEndpoint> {
    let class = admission_class(definition, stance)?;
    match class.authority_anchor {
        AuthorityAnchorRule::Subject => {
            let endpoint = created
                .endpoints
                .iter()
                .find(|endpoint| endpoint.role == "subject")
                .cloned()
                .ok_or_else(opaque_relationship)?;
            let record_id = endpoint
                .record_id
                .as_deref()
                .ok_or_else(opaque_relationship)?;
            if can_record_in(tx, caller, record_id, Capability::Edit).await? {
                Ok(endpoint)
            } else {
                Err(opaque_relationship())
            }
        }
        AuthorityAnchorRule::EitherEndpoint => {
            for endpoint in &created.endpoints {
                let Some(record_id) = endpoint.record_id.as_deref() else {
                    continue;
                };
                if can_record_in(tx, caller, record_id, Capability::Edit).await? {
                    return Ok(endpoint.clone());
                }
            }
            Err(opaque_relationship())
        }
        AuthorityAnchorRule::BoundEndpoint => {
            let person = crate::attribution::caller_person_in(tx, caller.credential())
                .await?
                .ok_or_else(opaque_relationship)?;
            let local_origin = local_origin_in(tx).await?;
            for endpoint in &created.endpoints {
                let (endpoint_origin, endpoint_record_id) =
                    crate::identity::decode_native_record(&endpoint.portable_ref)
                        .map_err(|_| opaque_relationship())?;
                if endpoint_origin == local_origin && endpoint_record_id == person {
                    return Ok(endpoint.clone());
                }
            }
            Err(opaque_relationship())
        }
    }
}

#[allow(clippy::too_many_arguments)] // closed payload constructor keeps every signed field explicit
fn assertion_created(
    caller: &Caller,
    stance: &str,
    on_behalf_of: Option<String>,
    rationale: Option<String>,
    valid_from: Option<String>,
    valid_until: Option<String>,
    causal_parents: Vec<CausalParentInput>,
    origin_admission: OriginAdmissionV1,
    attestation_id: &str,
) -> AssertionCreatedV1 {
    let mut parents = causal_parents
        .into_iter()
        .map(|parent| CausalAssertionParent {
            assertion_issuer_origin_db_id: parent.assertion_issuer_origin_db_id,
            assertion_id: parent.assertion_id,
            head_event_issuer_origin_db_id: parent.head_event_issuer_origin_db_id,
            head_event_id: parent.head_event_id,
            head_stream_version: parent.head_stream_version,
        })
        .collect::<Vec<_>>();
    parents.sort_by_key(|parent| {
        crate::derivation::canonical_json(&serde_json::to_value(parent).expect("parent serializes"))
    });
    parents.dedup();
    AssertionCreatedV1 {
        schema_version: 1,
        relationship: RelationshipCoordinate {
            relationship_origin_db_id: "00000000-0000-4000-8000-000000000000".into(),
            relationship_id: "00000000-0000-4000-8000-000000000000".into(),
            relationship_revision: 1,
        },
        relationship_created_event: RelationshipEventCoordinate {
            issuer_origin_db_id: "00000000-0000-4000-8000-000000000000".into(),
            event_id: "00000000-0000-4000-8000-000000000000".into(),
        },
        stance: stance.into(),
        semantic_claimant: caller.credential().into(),
        on_behalf_of,
        rationale,
        valid_from,
        valid_until,
        causal_parents: parents,
        origin_admission,
        authoring_action_attestation_id: attestation_id.into(),
    }
}

fn assertion_genesis_spec(
    origin: &str,
    caller: &Caller,
    now: &str,
    relationship: &ResolvedRelationship,
    mut assertion: AssertionCreatedV1,
) -> Result<RelationshipEventSpec> {
    assertion.relationship = relationship.coordinate.clone();
    assertion.relationship_created_event = relationship.created_event.clone();
    let spec = RelationshipEventSpec {
        event_id: Uuid::new_v4().to_string(),
        stream_id: Uuid::new_v4().to_string(),
        expected_stream_version: 0,
        relationship: relationship.coordinate.clone(),
        payload: RelationshipEventPayload::AssertionCreated(assertion),
        actor: caller.actor().into(),
        issuer_origin_db_id: origin.into(),
        occurred_at: now.into(),
        ingested_at: now.into(),
    };
    spec.validate()?;
    Ok(spec)
}

struct AssertionHeadForWrite {
    assertion_id: String,
    coordinate: RelationshipCoordinate,
    stream_version: i64,
    active: bool,
}

async fn authorize_assertion_mutation_in(
    tx: &mut Transaction<'static, Sqlite>,
    caller: &Caller,
    issuer: &str,
    assertion_id: &str,
) -> Result<AssertionHeadForWrite> {
    let origin = local_origin_in(tx).await?;
    if issuer != origin {
        return Err(opaque_relationship());
    }
    let locator = sqlx::query(
        "SELECT relationship_origin_db_id,relationship_id
           FROM relationship_assertion_heads
          WHERE issuer_origin_db_id=? AND assertion_id=?",
    )
    .bind(issuer)
    .bind(assertion_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(opaque_relationship)?;
    let relationship_origin: String = locator.try_get("relationship_origin_db_id")?;
    let relationship_id: String = locator.try_get("relationship_id")?;
    load_endpoints_and_authorize_in(tx, caller, &relationship_origin, &relationship_id).await?;
    // Only after endpoint non-disclosure succeeds may semantic claimant and
    // assertion state influence the result.
    let row = sqlx::query(
        "SELECT relationship_revision,stream_version,semantic_claimant,state
           FROM relationship_assertion_heads
          WHERE issuer_origin_db_id=? AND assertion_id=?
            AND relationship_origin_db_id=? AND relationship_id=?",
    )
    .bind(issuer)
    .bind(assertion_id)
    .bind(&relationship_origin)
    .bind(&relationship_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(opaque_relationship)?;
    if row.try_get::<String, _>("semantic_claimant")? != caller.credential() {
        return Err(opaque_relationship());
    }
    Ok(AssertionHeadForWrite {
        assertion_id: assertion_id.into(),
        coordinate: RelationshipCoordinate {
            relationship_origin_db_id: relationship_origin,
            relationship_id,
            relationship_revision: u64::try_from(row.try_get::<i64, _>("relationship_revision")?)
                .map_err(|_| opaque_relationship())?,
        },
        stream_version: row.try_get("stream_version")?,
        active: row.try_get::<String, _>("state")? == "active",
    })
}

fn next_assertion_event(
    caller: &Caller,
    origin: &str,
    assertion: &AssertionHeadForWrite,
    payload: RelationshipEventPayload,
) -> Result<RelationshipEventSpec> {
    let now = crate::store::now_iso();
    let spec = RelationshipEventSpec {
        event_id: Uuid::new_v4().to_string(),
        stream_id: assertion.assertion_id.clone(),
        expected_stream_version: assertion.stream_version,
        relationship: assertion.coordinate.clone(),
        payload,
        actor: caller.actor().into(),
        issuer_origin_db_id: origin.into(),
        occurred_at: now.clone(),
        ingested_at: now,
    };
    spec.validate()?;
    Ok(spec)
}

fn relationship_receipt(
    status: &str,
    origin: &str,
    relationship_id: &str,
    assertion_id: &str,
    assertion_stream_version: i64,
    output_events: &[(&str, &str)],
) -> Value {
    let action = match status {
        "asserted" => "assert",
        "contested" => "contest",
        "evidence_added" => "add_evidence",
        "retracted" => "retract",
        _ => "unknown",
    };
    json!({
        "action": action,
        "status": status,
        "relationship_origin_db_id": origin,
        "relationship_id": relationship_id,
        "relationship_revision": 1,
        "assertion_issuer_origin_db_id": origin,
        "assertion_id": assertion_id,
        "assertion_stream_version": assertion_stream_version,
        "output_events": output_events.iter().map(|(issuer, event_id)| json!({
            "domain": "relationship",
            "issuer_origin_db_id": issuer,
            "event_id": event_id,
        })).collect::<Vec<_>>(),
    })
}

async fn reconstruct_retry_in(
    tx: &mut Transaction<'_, Sqlite>,
    attestation_id: &str,
    action: &str,
) -> Result<Value> {
    let rows = sqlx::query(
        "SELECT o.ordinal,e.id,e.stream_id,e.stream_version,e.relationship_origin_db_id,
                e.relationship_id,e.type,e.payload,e.issuer_origin_db_id
           FROM provenance_action_outputs o
           JOIN relationship_events e ON o.output_domain='relationship'
             AND e.id=o.output_event_id
             AND e.issuer_origin_db_id=(SELECT issuer_origin_database_id
                                         FROM provenance_action_attestations WHERE id=o.action_attestation_id)
          WHERE o.action_attestation_id=? ORDER BY o.ordinal",
    )
    .bind(attestation_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Err(Error::engine(
            "manage_relationships: idempotent receipt is incomplete",
        ));
    }
    let assertion = rows
        .iter()
        .find(|row| {
            row.try_get::<String, _>("type")
                .ok()
                .is_some_and(|kind| kind.starts_with("assertion."))
        })
        .ok_or_else(|| Error::engine("manage_relationships: idempotent receipt is incomplete"))?;
    let origin: String = assertion.try_get("relationship_origin_db_id")?;
    let relationship_id: String = assertion.try_get("relationship_id")?;
    let assertion_id: String = assertion.try_get("stream_id")?;
    let assertion_stream_version: i64 = assertion.try_get("stream_version")?;
    let status = match action {
        "assert" => "asserted",
        "contest" => "contested",
        "add_evidence" => "evidence_added",
        "retract" => "retracted",
        _ => return Err(Error::engine("manage_relationships: invalid retry action")),
    };
    let output_events = rows
        .iter()
        .map(|row| {
            Ok((
                row.try_get::<String, _>("issuer_origin_db_id")?,
                row.try_get::<String, _>("id")?,
            ))
        })
        .collect::<std::result::Result<Vec<_>, sqlx::Error>>()?;
    let output_event_refs = output_events
        .iter()
        .map(|(issuer, event_id)| (issuer.as_str(), event_id.as_str()))
        .collect::<Vec<_>>();
    let mut response = relationship_receipt(
        status,
        &origin,
        &relationship_id,
        &assertion_id,
        assertion_stream_version,
        &output_event_refs,
    );
    if action == "add_evidence" {
        let payload: String = assertion.try_get("payload")?;
        let value: Value = serde_json::from_str(&payload)?;
        let evidence_ref = value
            .get("evidence_ref")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Error::engine("manage_relationships: idempotent receipt is incomplete")
            })?;
        let (_, evidence_id) = crate::identity::decode_native_record(evidence_ref)?;
        response["evidence_id"] = json!(evidence_id);
    }
    Ok(response)
}

async fn read_relationship(
    db: &Db,
    caller: &Caller,
    origin: &str,
    relationship_id: &str,
    why: bool,
) -> Result<Value> {
    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let result = async {
        let relationship = load_relationship_in(&mut tx, caller, origin, relationship_id).await?;
        let evidence_rows = sqlx::query(
            "SELECT e.id,e.issuer_origin_db_id,e.stream_id,e.stream_version,e.type,e.payload,e.occurred_at,
                    h.stance,h.state,h.semantic_claimant,h.on_behalf_of,h.rationale,
                    h.valid_from,h.valid_until,h.causal_parents,h.origin_admission,
                    h.authoring_action_attestation_id,h.last_event_issuer_origin_db_id,
                    h.last_event_id,l.local_admission_state,l.local_admission_class,
                    (SELECT o.action_attestation_id
                       FROM provenance_action_outputs o
                       JOIN provenance_action_attestations a ON a.id=o.action_attestation_id
                      WHERE o.output_domain='relationship' AND o.output_event_id=e.id
                        AND a.issuer_origin_database_id=e.issuer_origin_db_id
                      ORDER BY o.action_attestation_id LIMIT 1) AS event_action_attestation_id
               FROM relationship_events e
               JOIN relationship_assertion_heads h
                 ON h.issuer_origin_db_id=e.issuer_origin_db_id AND h.assertion_id=e.stream_id
               LEFT JOIN relationship_local_admissions l
                 ON l.issuer_origin_db_id=h.issuer_origin_db_id AND l.assertion_id=h.assertion_id
              WHERE e.relationship_origin_db_id=? AND e.relationship_id=?
                AND e.stream_kind='assertion'
              ORDER BY e.issuer_origin_db_id,e.stream_id,e.stream_version",
        )
        .bind(origin)
        .bind(relationship_id)
        .fetch_all(&mut *tx)
        .await?;
        let mut assertions = BTreeMap::<(String, String), Value>::new();
        let mut attestation_ids = Vec::new();
        for row in evidence_rows {
            let issuer: String = row.try_get("issuer_origin_db_id")?;
            let assertion_id: String = row.try_get("stream_id")?;
            let event_type: String = row.try_get("type")?;
            let payload: Value = serde_json::from_str(&row.try_get::<String, _>("payload")?)?;
            let entry = assertions.entry((issuer.clone(), assertion_id.clone())).or_insert_with(|| {
                json!({
                    "assertion_issuer_origin_db_id": issuer,
                    "assertion_id": assertion_id,
                    "stance": row.try_get::<String, _>("stance").unwrap_or_default(),
                    "state": row.try_get::<String, _>("state").unwrap_or_default(),
                    "semantic_claimant": row.try_get::<String, _>("semantic_claimant").unwrap_or_default(),
                    "on_behalf_of": row.try_get::<Option<String>, _>("on_behalf_of").unwrap_or(None),
                    "rationale": row.try_get::<Option<String>, _>("rationale").unwrap_or(None),
                    "valid_from": row.try_get::<Option<String>, _>("valid_from").unwrap_or(None),
                    "valid_until": row.try_get::<Option<String>, _>("valid_until").unwrap_or(None),
                    "causal_parents": serde_json::from_str::<Value>(&row.try_get::<String, _>("causal_parents").unwrap_or_else(|_| "[]".into())).unwrap_or_else(|_| json!([])),
                    "head": {
                        "issuer_origin_db_id": row.try_get::<String, _>("last_event_issuer_origin_db_id").unwrap_or_default(),
                        "event_id": row.try_get::<String, _>("last_event_id").unwrap_or_default(),
                        "stream_version": row.try_get::<i64, _>("stream_version").unwrap_or_default(),
                    },
                    "local_admission": {
                        "state": row.try_get::<String, _>("local_admission_state").unwrap_or_else(|_| "unresolved".into()),
                        "class": row.try_get::<Option<String>, _>("local_admission_class").unwrap_or(None),
                    },
                    "origin_admission": serde_json::from_str::<Value>(&row.try_get::<String, _>("origin_admission").unwrap_or_else(|_| "null".into())).unwrap_or(Value::Null),
                    "events": [],
                    "evidence": [],
                })
            });
            entry["events"].as_array_mut().expect("events array").push(json!({
                "stream_version": row.try_get::<i64, _>("stream_version")?,
                "type": event_type,
                "occurred_at": row.try_get::<String, _>("occurred_at")?,
                "payload": payload,
            }));
            if let Some(attestation_id) =
                row.try_get::<Option<String>, _>("event_action_attestation_id")?
            {
                attestation_ids.push(attestation_id);
            }
            if event_type == "assertion.created.v1" {
                attestation_ids.push(row.try_get::<String, _>("authoring_action_attestation_id")?);
            } else if event_type == "assertion.evidence_added.v1" {
                let evidence_ref = payload.get("evidence_ref").and_then(Value::as_str).ok_or_else(opaque_relationship)?;
                let (evidence_origin, evidence_id) = crate::identity::decode_native_record(evidence_ref)?;
                if evidence_origin != local_origin_in(&mut tx).await?
                    || !can_record_in(&mut tx, caller, &evidence_id, Capability::View).await?
                {
                    return Err(opaque_relationship());
                }
                entry["evidence"].as_array_mut().expect("evidence array").push(json!({
                    "record_id": evidence_id,
                    "reason": payload.get("reason").cloned().unwrap_or(Value::Null),
                }));
            }
        }
        let effective = sqlx::query(
            "SELECT effective_state,epistemic_state,support_count,contest_count,
                    admission_counts,reducer_id,reducer_version,assertion_set_digest,
                    knowledge_watermark,recomputed_at
               FROM effective_relationships
              WHERE relationship_origin_db_id=? AND relationship_id=?",
        )
        .bind(origin)
        .bind(relationship_id)
        .fetch_one(&mut *tx)
        .await?;
        let mut response = json!({
            "action": if why { "why" } else { "read" },
            "relationship_origin_db_id": origin,
            "relationship_id": relationship_id,
            "relationship_type": relationship.created.relationship_type,
            "type_definition_id": relationship.created.type_definition_id,
            "canonical_proposition_key": relationship.created.canonical_proposition_key,
            "endpoints": relationship.created.endpoints,
            "effective": {
                "state": effective.try_get::<String, _>("effective_state")?,
                "epistemic_state": effective.try_get::<String, _>("epistemic_state")?,
                "support_count": effective.try_get::<i64, _>("support_count")?,
                "contest_count": effective.try_get::<i64, _>("contest_count")?,
                "admission_counts": serde_json::from_str::<Value>(&effective.try_get::<String, _>("admission_counts")?)?,
                "reducer_id": effective.try_get::<String, _>("reducer_id")?,
                "reducer_version": effective.try_get::<i64, _>("reducer_version")?,
                "assertion_set_digest": effective.try_get::<String, _>("assertion_set_digest")?,
                "knowledge_watermark": serde_json::from_str::<Value>(&effective.try_get::<String, _>("knowledge_watermark")?)?,
                "recomputed_at": effective.try_get::<String, _>("recomputed_at")?,
            },
            "assertions": assertions.into_values().collect::<Vec<_>>(),
        });
        if why {
            if !crate::provenance::state_violations_in(&mut tx)
                .await?
                .is_empty()
            {
                return Err(opaque_relationship());
            }
            attestation_ids.sort();
            attestation_ids.dedup();
            let mut provenance = Vec::new();
            for attestation_id in attestation_ids {
                let inspection = crate::provenance::inspect_action_attestation_in(
                    &mut tx,
                    caller,
                    &attestation_id,
                    InspectionDetail::Why,
                    None,
                )
                .await?
                .ok_or_else(opaque_relationship)?;
                provenance.push(serde_json::to_value(inspection)?);
            }
            response["authorized_action_provenance"] = json!(provenance);
        }
        Ok(response)
    }
    .await;
    tx.rollback().await?;
    result
}

/// Viewer-scoped filters for the `find` read. Kept as one struct so the
/// dispatch arm stays a single call and the handler signature does not grow a
/// nine-argument positional list.
struct FindArgs {
    endpoint_record_id: Option<String>,
    endpoint_current_person: bool,
    relationship_type: Option<String>,
    endpoint_role: Option<String>,
    effective_state: Option<String>,
    epistemic_state: Option<String>,
    counterpart_lifecycle: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

const FIND_DEFAULT_LIMIT: i64 = 25;
const FIND_MAX_LIMIT: i64 = 200;
/// Hard ceiling on candidate rows examined per `find` call. Visibility is a
/// per-record policy fold that SQL cannot express, so the page is assembled by
/// filtering candidates in Rust; this cap keeps that work bounded rather than
/// letting one call walk an unbounded endpoint fan-out. Nothing here re-runs
/// the reducer: `effective_relationships` is read as the projector left it.
const FIND_CANDIDATE_SCAN_CAP: i64 = 2000;

const FIND_EFFECTIVE_STATES: [&str; 4] = ["active", "inactive", "unresolved", "retired"];
const FIND_EPISTEMIC_STATES: [&str; 4] = ["unsupported", "supported", "contested", "incomplete"];

fn find_enum(field: &str, value: &Option<String>, allowed: &[&str]) -> Result<()> {
    if let Some(value) = value {
        if !allowed.contains(&value.as_str()) {
            return Err(Error::engine(format!(
                "manage_relationships: find {field} must be one of {}",
                allowed.join(", ")
            )));
        }
    }
    Ok(())
}

async fn find_relationships(db: &Db, caller: &Caller, args: FindArgs) -> Result<Value> {
    let limit = args.limit.unwrap_or(FIND_DEFAULT_LIMIT);
    let offset = args.offset.unwrap_or(0);
    if limit <= 0 || limit > FIND_MAX_LIMIT {
        return Err(Error::engine(format!(
            "manage_relationships: find 'limit' must be between 1 and {FIND_MAX_LIMIT}"
        )));
    }
    if offset < 0 {
        return Err(Error::engine(
            "manage_relationships: find 'offset' must be a non-negative integer",
        ));
    }
    if offset + limit > FIND_CANDIDATE_SCAN_CAP {
        return Err(Error::engine(format!(
            "manage_relationships: find 'offset' + 'limit' must not exceed {FIND_CANDIDATE_SCAN_CAP}"
        )));
    }
    find_enum(
        "effective_state",
        &args.effective_state,
        &FIND_EFFECTIVE_STATES,
    )?;
    find_enum(
        "epistemic_state",
        &args.epistemic_state,
        &FIND_EPISTEMIC_STATES,
    )?;
    if let Some(relationship_type) = &args.relationship_type {
        // Reject ungoverned types with the same error `assert` uses, so `find`
        // never becomes a probe for which type vocabulary exists locally.
        definition(relationship_type)?;
    }
    if let Some(role) = &args.endpoint_role {
        require_nonblank("endpoint_role", role)?;
    }
    if let Some(lifecycle) = &args.counterpart_lifecycle {
        require_nonblank("counterpart_lifecycle", lifecycle)?;
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let result = async {
        let (scope_record_id, resolved_from) =
            match (args.endpoint_record_id.as_deref(), args.endpoint_current_person) {
                (Some(record_id), false) => {
                    require_nonblank("endpoint_record_id", record_id)?;
                    (record_id.to_owned(), "record_id")
                }
                (None, true) => {
                    let person = crate::attribution::caller_person_in(&mut tx, caller.credential())
                        .await?
                        .ok_or_else(|| {
                            Error::engine(
                                "manage_relationships: find endpoint_current_person requires a person bound to this caller",
                            )
                        })?;
                    (person, "current_person")
                }
                _ => {
                    return Err(Error::engine(
                        "manage_relationships: find requires exactly one of 'endpoint_record_id' or 'endpoint_current_person'",
                    ))
                }
            };
        // The scoped endpoint needs the same View capability every other
        // endpoint needs. The error text is `require_record_in`'s ("record
        // {id} does not exist"), NOT `opaque_relationship`'s: this is a
        // statement about the scoping record, before any relationship has been
        // named, so the record-shaped non-disclosure message is the accurate
        // one. Both are non-disclosing — an unviewable record and an absent
        // record are indistinguishable either way.
        require_record_in(
            &mut tx,
            caller,
            "manage_relationships",
            &scope_record_id,
            Capability::View,
        )
        .await?;

        // DELIBERATE: the counterpart join to `records` is INNER, so a
        // relationship whose counterpart endpoint has no local `record_id` (an
        // unbound or purely portable endpoint, which `assigned_to.v1` permits)
        // is absent from `find` results. That matches
        // `load_endpoints_and_authorize_in`, which already collapses a
        // null-`record_id` endpoint into the opaque error rather than
        // returning it: an endpoint the viewer cannot resolve to a local,
        // authorizable record is not shown by any read on this substrate.
        // Widening `find` to project unbound endpoints would make it the only
        // read that discloses them, so it is a separate decision, not a
        // side effect of this one. Pinned by
        // `find_omits_relationships_whose_counterpart_endpoint_is_unbound`.
        let mut sql = String::from(
            "SELECT r.relationship_origin_db_id AS rel_origin,
                    r.relationship_id AS rel_id,
                    r.relationship_type AS relationship_type,
                    r.type_definition_id AS type_definition_id,
                    r.occurred_at AS occurred_at,
                    eff.effective_state AS effective_state,
                    eff.epistemic_state AS epistemic_state,
                    eff.support_count AS support_count,
                    eff.contest_count AS contest_count,
                    eff.recomputed_at AS recomputed_at,
                    scope_ep.role AS scope_role,
                    other_ep.ordinal AS counterpart_ordinal,
                    other_ep.role AS counterpart_role,
                    other_ep.record_id AS counterpart_record_id,
                    other_ep.record_type AS counterpart_record_type,
                    other_ep.record_kind AS counterpart_record_kind,
                    other_ep.portable_ref AS counterpart_portable_ref,
                    rec.name AS counterpart_name,
                    rec.lifecycle AS counterpart_lifecycle
               FROM relationship_endpoints scope_ep
               JOIN relationships r
                 ON r.relationship_origin_db_id = scope_ep.relationship_origin_db_id
                AND r.relationship_id = scope_ep.relationship_id
               JOIN effective_relationships eff
                 ON eff.relationship_origin_db_id = r.relationship_origin_db_id
                AND eff.relationship_id = r.relationship_id
               JOIN relationship_endpoints other_ep
                 ON other_ep.relationship_origin_db_id = r.relationship_origin_db_id
                AND other_ep.relationship_id = r.relationship_id
                AND other_ep.ordinal <> scope_ep.ordinal
               JOIN records rec
                 ON rec.id = other_ep.record_id AND rec.deleted_at IS NULL
              WHERE scope_ep.record_id = ? AND r.status = 'active'",
        );
        if args.relationship_type.is_some() {
            sql.push_str(" AND r.relationship_type = ?");
        }
        if args.endpoint_role.is_some() {
            sql.push_str(" AND scope_ep.role = ?");
        }
        if args.effective_state.is_some() {
            sql.push_str(" AND eff.effective_state = ?");
        }
        if args.epistemic_state.is_some() {
            sql.push_str(" AND eff.epistemic_state = ?");
        }
        if args.counterpart_lifecycle.is_some() {
            sql.push_str(" AND rec.lifecycle = ?");
        }
        // Deterministic order: newest proposition first, with the relationship
        // coordinate (and then the counterpart ordinal) as a total tiebreak so
        // fixtures with equal timestamps still page identically every run.
        sql.push_str(
            " ORDER BY r.occurred_at DESC, r.relationship_origin_db_id ASC,
                       r.relationship_id ASC, other_ep.ordinal ASC
               LIMIT ?",
        );

        let scan_limit = (offset + limit + 1)
            .saturating_mul(4)
            .min(FIND_CANDIDATE_SCAN_CAP);
        let mut query = sqlx::query(&sql).bind(&scope_record_id);
        if let Some(value) = &args.relationship_type {
            query = query.bind(value);
        }
        if let Some(value) = &args.endpoint_role {
            query = query.bind(value);
        }
        if let Some(value) = &args.effective_state {
            query = query.bind(value);
        }
        if let Some(value) = &args.epistemic_state {
            query = query.bind(value);
        }
        if let Some(value) = &args.counterpart_lifecycle {
            query = query.bind(value);
        }
        let rows = query.bind(scan_limit).fetch_all(&mut *tx).await?;
        let scan_limit_reached = rows.len() as i64 >= scan_limit;

        let mut seen = std::collections::HashSet::new();
        let mut visible = Vec::new();
        let mut skipped = 0i64;
        let mut has_more = false;
        for row in rows {
            let origin: String = row.try_get("rel_origin")?;
            let relationship_id: String = row.try_get("rel_id")?;
            if !seen.insert((origin.clone(), relationship_id.clone())) {
                continue;
            }
            let counterpart_record_id: String = row.try_get("counterpart_record_id")?;
            // All-or-nothing endpoint visibility, matching
            // `load_endpoints_and_authorize_in`: an endpoint the viewer cannot
            // View removes the whole relationship from the result set. No
            // field is nulled or redacted, because a redacted row would still
            // disclose that the relationship exists. This filters WHICH rows
            // are shown; it never re-reduces a shown row, so a contest issued
            // from an invisible record still shows up as `contested` below.
            if !can_record_in(&mut tx, caller, &counterpart_record_id, Capability::View).await? {
                continue;
            }
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if visible.len() as i64 == limit {
                has_more = true;
                break;
            }
            visible.push(json!({
                "relationship_origin_db_id": origin,
                "relationship_id": relationship_id,
                "relationship_type": row.try_get::<String, _>("relationship_type")?,
                "type_definition_id": row.try_get::<String, _>("type_definition_id")?,
                "occurred_at": row.try_get::<String, _>("occurred_at")?,
                "endpoint": {
                    "record_id": scope_record_id,
                    "role": row.try_get::<String, _>("scope_role")?,
                },
                "counterpart": {
                    "role": row.try_get::<String, _>("counterpart_role")?,
                    "record_id": counterpart_record_id,
                    "record_type": row.try_get::<Option<String>, _>("counterpart_record_type")?,
                    "record_kind": row.try_get::<Option<String>, _>("counterpart_record_kind")?,
                    "portable_ref": row.try_get::<String, _>("counterpart_portable_ref")?,
                    "name": row.try_get::<String, _>("counterpart_name")?,
                    "lifecycle": row.try_get::<Option<String>, _>("counterpart_lifecycle")?,
                },
                "effective": {
                    "state": row.try_get::<String, _>("effective_state")?,
                    "epistemic_state": row.try_get::<String, _>("epistemic_state")?,
                    "support_count": row.try_get::<i64, _>("support_count")?,
                    "contest_count": row.try_get::<i64, _>("contest_count")?,
                    "recomputed_at": row.try_get::<String, _>("recomputed_at")?,
                },
            }));
        }
        Ok(json!({
            "action": "find",
            "endpoint": {
                "record_id": scope_record_id,
                "resolved_from": resolved_from,
            },
            "results": visible,
            "returned": visible.len(),
            "limit": limit,
            "offset": offset,
            "has_more": has_more,
            "scan_limit_reached": scan_limit_reached,
        }))
    }
    .await;
    tx.rollback().await?;
    result
}

pub fn register_relationship_tools(registry: &mut ToolRegistry) -> Result<()> {
    registry.register(
        ToolKind::ManageRelationships,
        "Assert, contest, evidence, retract, read, explain, or find governed semantic relationships. Endpoint identity, type metadata, admission evidence, canonical proposition identity, and action provenance are server-derived. Relationships never grant View, Edit, or Manage capability.",
        json!({
            "type": "object",
            "oneOf": [
                {
                    "type": "object",
                    "properties": {
                        "action": {"const": "assert"},
                        "relationship_type": {"type": "string", "enum": ["relates_to", "depends_on", "blocks", "assigned_to", "answerable_by"]},
                        "endpoints": {"type": "array", "minItems": 2, "maxItems": 2, "items": {"type": "object", "properties": {"role": {"type": "string"}, "record_id": {"type": "string"}}, "required": ["role", "record_id"], "additionalProperties": false}},
                        "identity_qualifiers": {"type": "object"},
                        "rationale": {"type": "string"},
                        "valid_from": {"type": "string"},
                        "valid_until": {"type": "string"},
                        "causal_parents": {"type": "array", "items": {"type": "object", "properties": {"assertion_issuer_origin_db_id":{"type":"string"},"assertion_id":{"type":"string"},"head_event_issuer_origin_db_id":{"type":"string"},"head_event_id":{"type":"string"},"head_stream_version":{"type":"integer","minimum":1}},"required":["assertion_issuer_origin_db_id","assertion_id","head_event_issuer_origin_db_id","head_event_id","head_stream_version"],"additionalProperties":false}},
                        "on_behalf_of": {"type": "string", "description": "Caller-authored semantic context only; never delegation or authority."},
                        "idempotency_key": {"type": "string", "minLength": 1, "maxLength": 200}
                    },
                    "required": ["action", "relationship_type", "endpoints", "idempotency_key"],
                    "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"action":{"const":"contest"},"relationship_origin_db_id":{"type":"string"},"relationship_id":{"type":"string"},"rationale":{"type":"string"},"causal_parents":{"type":"array","items":{"type":"object","properties":{"assertion_issuer_origin_db_id":{"type":"string"},"assertion_id":{"type":"string"},"head_event_issuer_origin_db_id":{"type":"string"},"head_event_id":{"type":"string"},"head_stream_version":{"type":"integer","minimum":1}},"required":["assertion_issuer_origin_db_id","assertion_id","head_event_issuer_origin_db_id","head_event_id","head_stream_version"],"additionalProperties":false}},"on_behalf_of":{"type":"string","description":"Caller-authored semantic context only; never delegation or authority."},"idempotency_key":{"type":"string","minLength":1,"maxLength":200}},
                    "required": ["action","relationship_origin_db_id","relationship_id","idempotency_key"], "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"action":{"const":"add_evidence"},"assertion_issuer_origin_db_id":{"type":"string"},"assertion_id":{"type":"string"},"evidence_id":{"type":"string"},"reason":{"type":"string","minLength":1},"idempotency_key":{"type":"string","minLength":1,"maxLength":200}},
                    "required": ["action","assertion_issuer_origin_db_id","assertion_id","evidence_id","reason","idempotency_key"], "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"action":{"const":"retract"},"assertion_issuer_origin_db_id":{"type":"string"},"assertion_id":{"type":"string"},"reason":{"type":"string","minLength":1},"idempotency_key":{"type":"string","minLength":1,"maxLength":200}},
                    "required": ["action","assertion_issuer_origin_db_id","assertion_id","reason","idempotency_key"], "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {"action":{"type":"string","enum":["read","why"]},"relationship_origin_db_id":{"type":"string"},"relationship_id":{"type":"string"}},
                    "required": ["action","relationship_origin_db_id","relationship_id"], "additionalProperties": false
                },
                {
                    "type": "object",
                    "properties": {
                        "action": {"const": "find"},
                        "endpoint_record_id": {"type": "string", "minLength": 1, "description": "Scope results to relationships with this record as an endpoint. Exactly one of endpoint_record_id or endpoint_current_person is required."},
                        "endpoint_current_person": {"type": "boolean", "description": "Scope results to the person record bound to the calling credential. Exactly one of endpoint_record_id or endpoint_current_person is required."},
                        "relationship_type": {"type": "string", "enum": ["relates_to", "depends_on", "blocks", "assigned_to", "answerable_by"]},
                        "endpoint_role": {"type": "string", "enum": ["subject", "object", "participant"], "description": "Role held by the scoped endpoint, i.e. direction. 'subject' returns relationships where the scoped record is the subject."},
                        "effective_state": {"type": "string", "enum": ["active", "inactive", "unresolved", "retired"]},
                        "epistemic_state": {"type": "string", "enum": ["unsupported", "supported", "contested", "incomplete"], "description": "Independent of effective_state: a contested assignment is never flattened into a supported one."},
                        "counterpart_lifecycle": {"type": "string", "minLength": 1, "description": "Lifecycle of the counterpart record, e.g. 'open'. Filtered server-side."},
                        "limit": {"type": "integer", "minimum": 1, "maximum": 200},
                        "offset": {"type": "integer", "minimum": 0}
                    },
                    "required": ["action"], "additionalProperties": false
                }
            ]
        }),
        manage_relationships,
    )?;
    Ok(())
}
