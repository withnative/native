//! Named artifact input binding governance.

use super::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub(super) enum ManageArtifactInputsArgs {
    Read {
        artifact_id: String,
    },
    Bind {
        artifact_id: String,
        port_name: String,
        collection_id: String,
    },
    Unbind {
        artifact_id: String,
        port_name: String,
        collection_id: String,
        event_seq: i64,
    },
}

pub(super) async fn manage_artifact_inputs(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "manage_artifact_inputs";
    let args: ManageArtifactInputsArgs = parse_args(TOOL, arguments)?;
    let artifact_id = match &args {
        ManageArtifactInputsArgs::Read { artifact_id }
        | ManageArtifactInputsArgs::Bind { artifact_id, .. }
        | ManageArtifactInputsArgs::Unbind { artifact_id, .. } => artifact_id.clone(),
    };
    match &args {
        ManageArtifactInputsArgs::Read { .. } => {
            require_record(&db, &caller, TOOL, &artifact_id, Capability::View).await?;
        }
        ManageArtifactInputsArgs::Bind { collection_id, .. } => {
            require_record(&db, &caller, TOOL, &artifact_id, Capability::Edit).await?;
            require_record(&db, &caller, TOOL, collection_id, Capability::View).await?;
        }
        ManageArtifactInputsArgs::Unbind { .. } => {
            require_record(&db, &caller, TOOL, &artifact_id, Capability::Edit).await?;
        }
    }
    if !live_v2_artifact(&db, &artifact_id).await? {
        return Err(Error::engine("manage_artifact_inputs: invalid artifact"));
    }
    match args {
        ManageArtifactInputsArgs::Read { .. } => {}
        ManageArtifactInputsArgs::Bind {
            port_name,
            collection_id,
            ..
        } => {
            if port_name == "default" || !valid_port_name(&port_name) {
                return Err(Error::engine(
                    "manage_artifact_inputs: invalid or reserved port name",
                ));
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_record_in(&mut tx, &caller, TOOL, &artifact_id, Capability::Edit).await?;
            require_record_in(&mut tx, &caller, TOOL, &collection_id, Capability::View).await?;
            let collection_kind = collection_kind_in(&mut tx, &collection_id)
                .await?
                .ok_or_else(|| {
                    Error::engine("manage_artifact_inputs: target must be a governed Collection")
                })?;
            let (artifact_source_event_id, artifact_source) =
                latest_body_source_in(&mut tx, &artifact_id).await?;
            let artifact_source_sha256 = mdx::sha256_hex(artifact_source.as_bytes());
            let attestation = sqlx::query(
                "SELECT attestation_event_id,source_sha256,descriptor
                   FROM artifact_source_attestations
                  WHERE artifact_id=? AND source_event_id=?",
            )
            .bind(&artifact_id)
            .bind(&artifact_source_event_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| {
                Error::engine(
                    "manage_artifact_inputs: exact artifact source attestation is missing",
                )
            })?;
            if attestation.try_get::<String, _>("source_sha256")? != artifact_source_sha256 {
                return Err(Error::engine(
                    "manage_artifact_inputs: artifact source attestation digest mismatch",
                ));
            }
            let artifact_source_attestation_event_id: String =
                attestation.try_get("attestation_event_id")?;
            let descriptor: Value =
                serde_json::from_str(&attestation.try_get::<String, _>("descriptor")?)?;
            let port_declaration = descriptor["artifact_ports"]
                .get(&port_name)
                .ok_or_else(|| {
                    Error::engine("manage_artifact_inputs: artifact does not declare this port")
                })?
                .clone();
            let declaration: mdx_v2::InputDecl = serde_json::from_value(port_declaration.clone())
                .map_err(|_| {
                Error::engine("manage_artifact_inputs: attested port declaration is invalid")
            })?;
            validate_input_binding_relation_in(
                &mut tx,
                &collection_id,
                &collection_kind,
                &declaration,
            )
            .await?;
            let current = sqlx::query(
                "SELECT collection_id,event_seq,artifact_source_attestation_event_id,
                        artifact_source_event_id,artifact_source_sha256
                   FROM artifact_inputs WHERE artifact_id=? AND port_name=?",
            )
            .bind(&artifact_id)
            .bind(&port_name)
            .fetch_optional(&mut *tx)
            .await?;
            if let Some(current) = current {
                let current_collection: String = current.try_get("collection_id")?;
                let exact_source = current
                    .try_get::<String, _>("artifact_source_attestation_event_id")?
                    == artifact_source_attestation_event_id
                    && current.try_get::<String, _>("artifact_source_event_id")?
                        == artifact_source_event_id
                    && current.try_get::<String, _>("artifact_source_sha256")?
                        == artifact_source_sha256;
                if current_collection == collection_id && exact_source {
                    tx.rollback().await?;
                    return Ok(json!({
                        "status": "unchanged", "artifact_id": artifact_id,
                        "bindings": [{ "port_name": port_name,
                            "collection_id": collection_id,
                            "event_seq": current.try_get::<i64,_>("event_seq")? }],
                    }));
                }
                if current_collection != collection_id {
                    return Err(Error::engine(format!(
                        "manage_artifact_inputs: port '{port_name}' changed or is already bound; re-read and explicitly unbind its exact current binding first"
                    )));
                }
            }
            let mut payload = ArtifactInputBoundPayload {
                artifact_id: artifact_id.clone(),
                port_name,
                collection_id,
                artifact_source_event_id,
                artifact_source_sha256,
                artifact_source_attestation_event_id,
                port_declaration,
                attestation_sha256: String::new(),
            };
            payload.attestation_sha256 =
                mdx_sha256_for_projection(&input_attestation_value(&payload));
            let previous_seq = previous_record_seq_in(&mut tx, &artifact_id).await?;
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: artifact_id.clone(),
                    event_type: "artifact.input_bound".into(),
                    payload: serde_json::to_value(payload)?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?;
            db.commit_content(tx).await?;
            return Ok(json!({ "status": "bound", "artifact_id": artifact_id,
                "previous_seq": previous_seq }));
        }
        ManageArtifactInputsArgs::Unbind {
            port_name,
            collection_id,
            event_seq,
            ..
        } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            require_record_in(&mut tx, &caller, TOOL, &artifact_id, Capability::Edit).await?;
            let exact: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM artifact_inputs
                  WHERE artifact_id=? AND port_name=? AND collection_id=? AND event_seq=?)",
            )
            .bind(&artifact_id)
            .bind(&port_name)
            .bind(&collection_id)
            .bind(event_seq)
            .fetch_one(&mut *tx)
            .await?;
            if !exact {
                return Err(Error::engine(format!(
                    "manage_artifact_inputs: binding for port '{port_name}' changed since it was read; re-read and retry"
                )));
            }
            let previous_seq = previous_record_seq_in(&mut tx, &artifact_id).await?;
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: artifact_id.clone(),
                    event_type: "artifact.input_unbound".into(),
                    payload: serde_json::to_value(ArtifactInputUnboundPayload {
                        artifact_id: artifact_id.clone(),
                        port_name,
                    })?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?;
            db.commit_content(tx).await?;
            return Ok(json!({ "status": "unbound", "artifact_id": artifact_id,
                "previous_seq": previous_seq }));
        }
    }
    let rows = sqlx::query(
        "SELECT port_name,collection_id,event_seq FROM artifact_inputs WHERE artifact_id=? ORDER BY port_name",
    )
    .bind(&artifact_id)
    .fetch_all(db.write_pool())
    .await?;
    let mut bindings = Vec::new();
    for row in rows {
        let collection_id = row.get::<String, _>("collection_id");
        if !can_record(&db, &caller, &collection_id, Capability::View).await? {
            continue;
        }
        bindings.push(json!({
            "port_name": row.get::<String,_>("port_name"),
            "collection_id": collection_id,
            "event_seq": row.get::<i64,_>("event_seq"),
        }));
    }
    Ok(json!({ "status": "ok", "artifact_id": artifact_id, "bindings": bindings }))
}
