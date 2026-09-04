//! Artifact capability grant mutation and attestation governance.

use super::*;

pub(super) fn valid_port_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

#[allow(clippy::too_many_arguments)]
pub(super) fn collect_grant_paths(
    parsed: &mdx_v2::ParsedSource,
    importer_kind: &str,
    importer_event_id: &str,
    parent_port_map: &BTreeMap<String, String>,
    releases: &BTreeMap<String, ReleaseMaterial>,
    target_event_id: &str,
    path: &mut Vec<Value>,
    visiting: &mut BTreeSet<String>,
    found: &mut Vec<(Vec<Value>, BTreeMap<String, String>)>,
) -> Result<()> {
    let imports = normalized_release_imports(parsed);
    let imports = imports.as_array().expect("normalized imports are an array");
    for (ordinal, import_ref) in parsed.imports.iter().enumerate() {
        let import = imports[ordinal].clone();
        let child_event_id = &import_ref.address.publication_event_id;
        let child = releases.get(child_event_id).ok_or_else(|| {
            Error::engine("grant path dependency is missing from the exact closure")
        })?;
        let child_port_map = resolved_port_map_from_import(
            &import,
            parent_port_map,
            parsed.manifest.inputs(),
            child.parsed.manifest.inputs(),
        )?;
        path.push(json!({
            "importer_kind": importer_kind,
            "importer_event_id": importer_event_id,
            "import_ordinal": ordinal,
            "import": import,
            "resolved_port_map": child_port_map,
        }));
        if child_event_id == target_event_id {
            found.push((path.clone(), child_port_map.clone()));
        }
        if visiting.insert(child_event_id.clone()) {
            collect_grant_paths(
                &child.parsed,
                "module_release",
                child_event_id,
                &child_port_map,
                releases,
                target_event_id,
                path,
                visiting,
                found,
            )?;
            visiting.remove(child_event_id);
        }
        path.pop();
    }
    Ok(())
}

/// Explain why a grant scope did not match any declared capability request.
///
/// A source declaration names a port under its own local name, `scope.port`.
/// A grant names the port that request *resolves to*: `artifact_port` at the root,
/// and both `module_port` and `artifact_port` through an import path. The two
/// spellings are deliberate — through an import the declared port and the root port
/// it resolves to are genuinely different ports, so collapsing them would make a
/// module grant ambiguous.
///
/// The cost lands on the caller who has only ever been shown `scope.port`: an agent
/// that authored the artifact copies that spelling into the grant and is refused.
/// `cannot create or broaden an exact request` then reads as a consent boundary
/// rather than a spelling, and sends the reader looking for an approval surface that
/// does not exist. So name the shape that was wanted, and what arrived instead.
fn grant_scope_refusal(payload: &ArtifactModuleGrantPayload, declared: &[Value]) -> Error {
    let root = payload.subject_kind == "artifact_source";
    let subject = if root { "root" } else { "subject" };
    let received =
        serde_json::to_string(&payload.scope).unwrap_or_else(|_| "<unserializable>".to_owned());
    let refused = |detail: &str| {
        Error::engine(format!(
            "artifact grant cannot create or broaden an exact {subject} request: {detail}"
        ))
    };
    let matching = declared
        .iter()
        .filter(|request| request["capability"] == payload.capability.as_str())
        .collect::<Vec<_>>();
    let Some(first) = matching.first() else {
        return refused(&format!(
            "the {subject} declares no {} capability request, and a grant never creates one",
            payload.capability,
        ));
    };
    if payload.capability != "input.read" {
        // Every capability but input.read is declared unscoped today, but read the
        // declaration rather than asserting that, so a later scoped capability does
        // not inherit a message that quietly stops being true.
        let declared_scope = serde_json::to_string(&first["scope"])
            .unwrap_or_else(|_| "<unserializable>".to_owned());
        return refused(&format!(
            "{} is declared with scope {declared_scope}, received {received}",
            payload.capability,
        ));
    }
    let ports = matching
        .iter()
        .filter_map(|request| request["scope"].get("port").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join(", ");
    if root {
        refused(&format!(
            "input.read scope must name the resolved root port as \
             {{\"artifact_port\":\"<port>\"}}, not the declaration's scope.port spelling; \
             declared port(s): {ports}; received {received}"
        ))
    } else {
        refused(&format!(
            "input.read scope must name both ports as \
             {{\"module_port\":\"<declared>\",\"artifact_port\":\"<resolved root>\"}}, \
             where module_port is the declaration's scope.port and artifact_port is the root \
             port it resolves to; declared module port(s): {ports}; received {received}"
        ))
    }
}

pub(crate) async fn build_grant_attestation_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    payload: &ArtifactModuleGrantPayload,
) -> Result<(Value, String)> {
    let (artifact_source_event_id, artifact_source) =
        latest_body_source_in(tx, &payload.artifact_id).await?;
    let source_attestation = sqlx::query(
        "SELECT attestation_event_id,source_sha256,descriptor
           FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=?",
    )
    .bind(&payload.artifact_id)
    .bind(&artifact_source_event_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("artifact grant exact source attestation is missing"))?;
    let artifact_source_sha256 = mdx::sha256_hex(artifact_source.as_bytes());
    if source_attestation.try_get::<String, _>("source_sha256")? != artifact_source_sha256 {
        return Err(Error::engine(
            "artifact grant source attestation digest does not match current source",
        ));
    }
    let artifact_source_descriptor: Value =
        serde_json::from_str(&source_attestation.try_get::<String, _>("descriptor")?)?;
    let runtime = artifact_source_descriptor
        .get("runtime")
        .and_then(Value::as_str)
        .unwrap_or(mdx_v2::RUNTIME_ID);
    if !supports_named_input_runtime(runtime) {
        return Err(Error::engine(
            "artifact grant source attestation names an unsupported runtime",
        ));
    }
    let artifact_ports = artifact_source_descriptor["artifact_ports"]
        .as_object()
        .ok_or_else(|| Error::engine("artifact grant source port attestation is malformed"))?
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    let (request, mapping_path) = if payload.subject_kind == "artifact_source" {
        if payload.subject_record_id != payload.artifact_id
            || payload.subject_event_id != artifact_source_event_id
            || payload.source_sha256 != mdx::sha256_hex(artifact_source.as_bytes())
        {
            return Err(Error::engine(
                "artifact source grant subject does not name the exact current source",
            ));
        }
        let request = artifact_source_descriptor["capability_requests"]
            .as_array()
            .expect("projected source attestation has capability requests")
            .iter()
            .find(|request| {
                request["capability"] == payload.capability
                    && if payload.capability == "input.read" {
                        payload
                            .scope
                            .as_object()
                            .is_some_and(|scope| scope.len() == 1)
                            && payload.scope.get("artifact_port").and_then(Value::as_str)
                                == request["scope"].get("port").and_then(Value::as_str)
                    } else {
                        payload.scope == request["scope"]
                    }
            })
            .ok_or_else(|| {
                grant_scope_refusal(
                    payload,
                    artifact_source_descriptor["capability_requests"]
                        .as_array()
                        .map_or(&[][..], Vec::as_slice),
                )
            })?;
        (request.clone(), Vec::new())
    } else if payload.subject_kind == "module_release" {
        if runtime != mdx_v2::RUNTIME_ID {
            return Err(Error::engine(
                "native.html.v1 artifacts cannot grant module-release capabilities",
            ));
        }
        let parse_source = artifact_source.clone();
        let parsed = tokio::task::spawn_blocking(move || mdx_v2::parse_artifact(&parse_source))
            .await
            .map_err(|_| Error::engine("native.mdx.v2 grant worker terminated unexpectedly"))?
            .map_err(|failure| mdx_v2_engine_error(&payload.artifact_id, failure))?;
        let descriptor_text: String = sqlx::query_scalar(
            "SELECT descriptor FROM module_releases
              WHERE publication_event_id=? AND module_record_id=? AND source_sha256=?",
        )
        .bind(&payload.subject_event_id)
        .bind(&payload.subject_record_id)
        .bind(&payload.source_sha256)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| Error::engine("artifact grant subject is not an exact module release"))?;
        let descriptor: Value = serde_json::from_str(&descriptor_text)?;
        let declared_request = descriptor["capability_requests"]
            .as_array()
            .and_then(|requests| {
                requests.iter().find(|request| {
                    request["capability"] == payload.capability
                        && if payload.capability == "input.read" {
                            request["scope"].get("port").and_then(Value::as_str)
                                == payload.scope.get("module_port").and_then(Value::as_str)
                        } else {
                            request["scope"] == payload.scope
                        }
                })
            })
            .cloned()
            .ok_or_else(|| {
                grant_scope_refusal(
                    payload,
                    descriptor["capability_requests"]
                        .as_array()
                        .map_or(&[][..], Vec::as_slice),
                )
            })?;
        let closure =
            resolve_closure_in(tx, &parsed, caller.hosting_principal().unwrap_or("local"))
                .await
                .map_err(|failure| mdx_v2_engine_error(&payload.artifact_id, failure))?;
        let release = closure
            .get(&payload.subject_event_id)
            .filter(|release| {
                release.address.module_record_id == payload.subject_record_id
                    && release.address.source_sha256 == payload.source_sha256
            })
            .ok_or_else(|| {
                Error::engine("artifact grant subject is not in the exact release closure")
            })?;
        if !release
            .parsed
            .manifest
            .capability_requests()
            .iter()
            .any(|request| serde_json::to_value(request).ok().as_ref() == Some(&declared_request))
        {
            return Err(Error::engine(
                "artifact grant subject descriptor does not match its verified release",
            ));
        }
        let root_port_map = artifact_ports
            .iter()
            .map(|port| (port.clone(), port.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut paths = Vec::new();
        collect_grant_paths(
            &parsed,
            "artifact_source",
            &artifact_source_event_id,
            &root_port_map,
            &closure,
            &payload.subject_event_id,
            &mut Vec::new(),
            &mut BTreeSet::new(),
            &mut paths,
        )?;
        if payload.capability == "input.read" {
            let module_port = payload.scope.get("module_port").and_then(Value::as_str);
            let artifact_port = payload.scope.get("artifact_port").and_then(Value::as_str);
            paths.retain(|(_, ports)| {
                module_port.and_then(|port| ports.get(port).map(String::as_str)) == artifact_port
            });
        }
        paths.sort_by_key(|(path, _)| mdx_v2::canonical_json_bytes(&json!(path)));
        let (path, _) = paths.into_iter().next().ok_or_else(|| {
            Error::engine(
                "artifact grant request has no full exact port-forwarding path to the root",
            )
        })?;
        (declared_request, path)
    } else {
        return Err(Error::engine(
            "artifact capability grant subject_kind must be module_release or artifact_source",
        ));
    };
    let attestation = json!({
        "schema": if runtime == HTML_RUNTIME {
            "native.html.grant-attestation.v1"
        } else {
            "native.mdx.grant-attestation.v1"
        },
        "artifact_id": payload.artifact_id,
        "artifact_source_attestation_event_id": source_attestation
            .try_get::<String, _>("attestation_event_id")?,
        "artifact_source_event_id": artifact_source_event_id,
        "artifact_source_sha256": artifact_source_sha256,
        "artifact_ports": artifact_ports,
        "subject_kind": payload.subject_kind,
        "subject_record_id": payload.subject_record_id,
        "subject_event_id": payload.subject_event_id,
        "subject_source_sha256": payload.source_sha256,
        "subject_request": request,
        "mapping_path": mapping_path,
    });
    let digest = mdx_sha256_for_projection(&attestation);
    Ok((attestation, digest))
}

/// Re-attest an inherited grant, distinguishing an expected graph/request/path
/// incompatibility from an integrity or operational failure. Only the former
/// may be converted into a caller-visible partial carry; every error still
/// aborts the surrounding body-edit transaction.
pub(crate) async fn try_build_carried_grant_attestation_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    payload: &ArtifactModuleGrantPayload,
) -> Result<Option<(Value, String)>> {
    let (artifact_source_event_id, artifact_source) =
        latest_body_source_in(tx, &payload.artifact_id).await?;
    let source_attestation = sqlx::query(
        "SELECT descriptor FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=?",
    )
    .bind(&payload.artifact_id)
    .bind(&artifact_source_event_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| Error::engine("artifact carry exact source attestation is missing"))?;
    let descriptor: Value =
        serde_json::from_str(&source_attestation.try_get::<String, _>("descriptor")?)?;

    if payload.subject_kind == "artifact_source" {
        let compatible = descriptor["capability_requests"]
            .as_array()
            .ok_or_else(|| Error::engine("artifact carry capability requests are malformed"))?
            .iter()
            .any(|request| {
                request["capability"] == payload.capability
                    && if payload.capability == "input.read" {
                        payload
                            .scope
                            .as_object()
                            .is_some_and(|scope| scope.len() == 1)
                            && payload.scope.get("artifact_port").and_then(Value::as_str)
                                == request["scope"].get("port").and_then(Value::as_str)
                    } else {
                        payload.scope.as_object().is_some_and(Map::is_empty)
                            && payload.scope == request["scope"]
                    }
            });
        if !compatible {
            return Ok(None);
        }
    } else if payload.subject_kind == "module_release" {
        if descriptor
            .get("runtime")
            .and_then(Value::as_str)
            .is_some_and(|runtime| runtime == HTML_RUNTIME)
        {
            return Ok(None);
        }
        let parse_source = artifact_source;
        let parsed = tokio::task::spawn_blocking(move || mdx_v2::parse_artifact(&parse_source))
            .await
            .map_err(|_| Error::engine("native.mdx.v2 carry worker terminated unexpectedly"))?
            .map_err(|failure| mdx_v2_engine_error(&payload.artifact_id, failure))?;
        let closure =
            resolve_closure_in(tx, &parsed, caller.hosting_principal().unwrap_or("local"))
                .await
                .map_err(|failure| mdx_v2_engine_error(&payload.artifact_id, failure))?;
        let Some(release) = closure.get(&payload.subject_event_id) else {
            return Ok(None);
        };
        if release.address.module_record_id != payload.subject_record_id
            || release.address.source_sha256 != payload.source_sha256
        {
            return Ok(None);
        }
        let artifact_ports = descriptor["artifact_ports"]
            .as_object()
            .ok_or_else(|| Error::engine("artifact carry source ports are malformed"))?
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        let root_port_map = artifact_ports
            .iter()
            .map(|port| (port.clone(), port.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut paths = Vec::new();
        collect_grant_paths(
            &parsed,
            "artifact_source",
            &artifact_source_event_id,
            &root_port_map,
            &closure,
            &payload.subject_event_id,
            &mut Vec::new(),
            &mut BTreeSet::new(),
            &mut paths,
        )?;
        if payload.capability == "input.read" {
            let module_port = payload.scope.get("module_port").and_then(Value::as_str);
            let artifact_port = payload.scope.get("artifact_port").and_then(Value::as_str);
            paths.retain(|(_, ports)| {
                module_port.and_then(|port| ports.get(port).map(String::as_str)) == artifact_port
            });
        }
        if paths.is_empty() {
            return Ok(None);
        }
    } else {
        return Err(Error::engine(
            "artifact carry grant subject_kind is invalid",
        ));
    }

    build_grant_attestation_in(tx, caller, payload)
        .await
        .map(Some)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "action", rename_all = "snake_case")]
pub(super) enum ManageArtifactModuleGrantsArgs {
    Read {
        artifact_id: String,
    },
    Grant {
        artifact_id: String,
        subject_kind: String,
        subject_record_id: String,
        subject_event_id: String,
        source_sha256: String,
        capability: String,
        scope: Value,
        if_previous_seq: Option<i64>,
    },
    Revoke {
        artifact_id: String,
        subject_kind: String,
        subject_record_id: String,
        subject_event_id: String,
        source_sha256: String,
        capability: String,
        scope: Value,
        if_previous_seq: Option<i64>,
    },
}

#[cfg(feature = "mcp-executor-prototype")]
#[derive(Clone, Debug)]
pub(crate) struct ArtifactModuleGrantPreparation {
    pub target_id: String,
    pub target_name: String,
    pub state_revision: String,
    pub target_state_digest: String,
    pub effect: Value,
    pub canonical_source_arguments: Value,
}

#[cfg(feature = "mcp-executor-prototype")]
pub(super) fn artifact_grant_mutation_action(
    arguments: &ManageArtifactModuleGrantsArgs,
) -> Option<&'static str> {
    match arguments {
        ManageArtifactModuleGrantsArgs::Grant { .. } => Some("grant"),
        ManageArtifactModuleGrantsArgs::Revoke { .. } => Some("revoke"),
        ManageArtifactModuleGrantsArgs::Read { .. } => None,
    }
}

pub(super) fn assert_artifact_previous_seq(
    artifact_id: &str,
    actual: Option<i64>,
    expected: Option<i64>,
) -> Result<()> {
    if expected.is_some() && expected != actual {
        return Err(Error::engine(format!(
            "manage_artifact_module_grants: artifact {artifact_id} changed since preparation; re-read and retry"
        )));
    }
    Ok(())
}

#[cfg(feature = "mcp-executor-prototype")]
pub(crate) fn validate_artifact_module_grant_mutation(
    expected_action: &str,
    arguments: Value,
) -> Result<()> {
    const TOOL: &str = "manage_artifact_module_grants";
    let arguments: ManageArtifactModuleGrantsArgs = parse_args(TOOL, arguments)?;
    if artifact_grant_mutation_action(&arguments) != Some(expected_action) {
        return Err(Error::engine(format!(
            "{TOOL}: executor preparation expected action {expected_action}"
        )));
    }
    Ok(())
}

/// Exercise the exact production parser, authorization, grant attestation and
/// projection verifier without appending an event. The canonical source
/// arguments carry the current record sequence so the production handler can
/// enforce the approved state inside its own write transaction.
#[cfg(feature = "mcp-executor-prototype")]
pub(crate) async fn prepare_artifact_module_grant_mutation(
    db: &Db,
    caller: &Caller,
    expected_action: &str,
    arguments: Value,
) -> Result<ArtifactModuleGrantPreparation> {
    const TOOL: &str = "manage_artifact_module_grants";
    let mut canonical_source_arguments = arguments.clone();
    let arguments: ManageArtifactModuleGrantsArgs = parse_args(TOOL, arguments)?;
    if artifact_grant_mutation_action(&arguments) != Some(expected_action) {
        return Err(Error::engine(format!(
            "{TOOL}: executor preparation expected action {expected_action}"
        )));
    }
    let (
        artifact_id,
        subject_kind,
        subject_record_id,
        subject_event_id,
        source_sha256,
        capability,
        scope,
        expected_previous_seq,
        revoke,
    ) = match arguments {
        ManageArtifactModuleGrantsArgs::Grant {
            artifact_id,
            subject_kind,
            subject_record_id,
            subject_event_id,
            source_sha256,
            capability,
            scope,
            if_previous_seq,
        } => (
            artifact_id,
            subject_kind,
            subject_record_id,
            subject_event_id,
            source_sha256,
            capability,
            scope,
            if_previous_seq,
            false,
        ),
        ManageArtifactModuleGrantsArgs::Revoke {
            artifact_id,
            subject_kind,
            subject_record_id,
            subject_event_id,
            source_sha256,
            capability,
            scope,
            if_previous_seq,
        } => (
            artifact_id,
            subject_kind,
            subject_record_id,
            subject_event_id,
            source_sha256,
            capability,
            scope,
            if_previous_seq,
            true,
        ),
        ManageArtifactModuleGrantsArgs::Read { .. } => {
            unreachable!("mutation action checked above")
        }
    };

    require_record(db, caller, TOOL, &artifact_id, Capability::Edit).await?;
    if !live_v2_artifact(db, &artifact_id).await? {
        return Err(Error::engine(
            "manage_artifact_module_grants: invalid artifact",
        ));
    }
    if !revoke {
        require_record(db, caller, TOOL, &subject_record_id, Capability::View).await?;
    }
    if !is_supported_grant_capability(&capability) {
        return Err(Error::engine(
            "manage_artifact_module_grants: runtime does not support this capability",
        ));
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    require_record_in(&mut tx, caller, TOOL, &artifact_id, Capability::Edit).await?;
    if !revoke {
        require_record_in(&mut tx, caller, TOOL, &subject_record_id, Capability::View).await?;
    }
    let previous_seq = previous_record_seq_in(&mut tx, &artifact_id).await?;
    assert_artifact_previous_seq(&artifact_id, previous_seq, expected_previous_seq)?;
    let previous_seq_value = previous_seq.ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: artifact {artifact_id} has no authoritative content revision"
        ))
    })?;
    canonical_source_arguments
        .as_object_mut()
        .expect("production artifact grant arguments parsed as an object")
        .insert("if_previous_seq".into(), json!(previous_seq_value));

    let scope_sha256 = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&scope));
    let mut payload = ArtifactModuleGrantPayload {
        artifact_id: artifact_id.clone(),
        subject_kind,
        subject_record_id,
        subject_event_id,
        source_sha256,
        capability,
        scope,
        scope_sha256,
        attestation: None,
        attestation_sha256: None,
    };
    let existing = sqlx::query(
        "SELECT event_seq,artifact_source_attestation_event_id,artifact_source_event_id,
                artifact_source_sha256
           FROM artifact_module_grants
          WHERE artifact_id=? AND subject_kind=? AND subject_record_id=? AND subject_event_id=?
            AND source_sha256=? AND capability=? AND scope_sha256=?",
    )
    .bind(&artifact_id)
    .bind(&payload.subject_kind)
    .bind(&payload.subject_record_id)
    .bind(&payload.subject_event_id)
    .bind(&payload.source_sha256)
    .bind(&payload.capability)
    .bind(&payload.scope_sha256)
    .fetch_optional(&mut *tx)
    .await?;
    if revoke && existing.is_none() {
        return Err(Error::engine(
            "manage_artifact_module_grants: exact grant changed or no longer exists; re-read and retry",
        ));
    }
    if !revoke {
        let _permit =
            mdx::try_admit().map_err(|failure| mdx_v2_engine_error(&artifact_id, failure))?;
        let (attestation, attestation_sha256) =
            build_grant_attestation_in(&mut tx, caller, &payload).await?;
        payload.attestation = Some(attestation);
        payload.attestation_sha256 = Some(attestation_sha256);
        verify_mdx_grant_for_projection(&mut tx, &payload, i64::MAX).await?;
    }
    let target_name: String =
        sqlx::query_scalar("SELECT name FROM records WHERE id=? AND deleted_at IS NULL")
            .bind(&artifact_id)
            .fetch_one(&mut *tx)
            .await?;
    let existing_state = existing.map(|row| {
        json!({
            "event_seq": row.get::<i64, _>("event_seq"),
            "artifact_source_attestation_event_id": row.get::<String, _>("artifact_source_attestation_event_id"),
            "artifact_source_event_id": row.get::<String, _>("artifact_source_event_id"),
            "artifact_source_sha256": row.get::<String, _>("artifact_source_sha256"),
        })
    });
    let target_state = json!({
        "artifact_id": artifact_id,
        "name": target_name,
        "previous_seq": previous_seq_value,
        "exact_grant": existing_state,
    });
    let target_state_digest = hex::encode(sha2::Sha256::digest(serde_jcs::to_vec(&target_state)?));
    let effect = json!({
        "action": expected_action,
        "target": {"artifact_id": artifact_id, "name": target_name},
        "grant": {
            "subject_kind": payload.subject_kind,
            "subject_record_id": payload.subject_record_id,
            "subject_event_id": payload.subject_event_id,
            "source_sha256": payload.source_sha256,
            "capability": payload.capability,
            "scope": payload.scope,
            "scope_sha256": payload.scope_sha256,
            "attestation_sha256": payload.attestation_sha256,
        },
        "before": {"present": existing_state.is_some(), "state": existing_state},
        "after": {"present": !revoke},
        "changed": true,
    });
    tx.rollback().await?;
    Ok(ArtifactModuleGrantPreparation {
        target_id: artifact_id,
        target_name,
        state_revision: previous_seq_value.to_string(),
        target_state_digest,
        effect,
        canonical_source_arguments,
    })
}

pub(super) async fn manage_artifact_module_grants(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "manage_artifact_module_grants";
    let args: ManageArtifactModuleGrantsArgs = parse_args(TOOL, arguments)?;
    let artifact_id = match &args {
        ManageArtifactModuleGrantsArgs::Read { artifact_id }
        | ManageArtifactModuleGrantsArgs::Grant { artifact_id, .. }
        | ManageArtifactModuleGrantsArgs::Revoke { artifact_id, .. } => artifact_id.clone(),
    };
    let required = if matches!(&args, ManageArtifactModuleGrantsArgs::Read { .. }) {
        Capability::View
    } else {
        Capability::Edit
    };
    require_record(&db, &caller, TOOL, &artifact_id, required).await?;
    if !live_v2_artifact(&db, &artifact_id).await? {
        return Err(Error::engine(
            "manage_artifact_module_grants: invalid artifact",
        ));
    }
    let revoke = matches!(&args, ManageArtifactModuleGrantsArgs::Revoke { .. });
    if let ManageArtifactModuleGrantsArgs::Grant {
        subject_record_id, ..
    } = &args
    {
        require_record(&db, &caller, TOOL, subject_record_id, Capability::View).await?;
    }
    if let ManageArtifactModuleGrantsArgs::Grant {
        subject_kind,
        subject_record_id,
        subject_event_id,
        source_sha256,
        capability,
        scope,
        if_previous_seq,
        ..
    }
    | ManageArtifactModuleGrantsArgs::Revoke {
        subject_kind,
        subject_record_id,
        subject_event_id,
        source_sha256,
        capability,
        scope,
        if_previous_seq,
        ..
    } = args
    {
        if !is_supported_grant_capability(&capability) {
            return Err(Error::engine(
                "manage_artifact_module_grants: runtime does not support this capability",
            ));
        }
        let mut tx = crate::db::begin_write(db.write_pool()).await?;
        require_record_in(&mut tx, &caller, TOOL, &artifact_id, Capability::Edit).await?;
        if !revoke {
            require_record_in(&mut tx, &caller, TOOL, &subject_record_id, Capability::View).await?;
        }
        let previous_seq = previous_record_seq_in(&mut tx, &artifact_id).await?;
        assert_artifact_previous_seq(&artifact_id, previous_seq, if_previous_seq)?;
        let scope_sha256 = mdx::sha256_hex(&mdx_v2::canonical_json_bytes(&scope));
        let mut payload = ArtifactModuleGrantPayload {
            artifact_id: artifact_id.clone(),
            subject_kind,
            subject_record_id,
            subject_event_id,
            source_sha256,
            capability,
            scope,
            scope_sha256,
            attestation: None,
            attestation_sha256: None,
        };
        if revoke {
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM artifact_module_grants
                  WHERE artifact_id=? AND subject_kind=? AND subject_record_id=? AND subject_event_id=?
                    AND source_sha256=? AND capability=? AND scope_sha256=?)",
            )
            .bind(&artifact_id)
            .bind(&payload.subject_kind)
            .bind(&payload.subject_record_id)
            .bind(&payload.subject_event_id)
            .bind(&payload.source_sha256)
            .bind(&payload.capability)
            .bind(&payload.scope_sha256)
            .fetch_one(&mut *tx)
            .await?;
            if !exists {
                return Err(Error::engine(
                    "manage_artifact_module_grants: exact grant changed or no longer exists; re-read and retry",
                ));
            }
            append_in(
                &db,
                &mut tx,
                AppendSpec {
                    record_id: artifact_id.clone(),
                    event_type: "artifact.module_grant_unset".into(),
                    payload: serde_json::to_value(payload)?,
                    actor: Some(caller.actor().into()),
                },
            )
            .await?;
            db.commit_content(tx).await?;
            return Ok(json!({ "status": "revoked", "artifact_id": artifact_id,
                "previous_seq": previous_seq }));
        }
        let _permit =
            mdx::try_admit().map_err(|failure| mdx_v2_engine_error(&artifact_id, failure))?;
        let (attestation, attestation_sha256) =
            build_grant_attestation_in(&mut tx, &caller, &payload).await?;
        payload.attestation = Some(attestation);
        payload.attestation_sha256 = Some(attestation_sha256);
        verify_mdx_grant_for_projection(&mut tx, &payload, i64::MAX).await?;
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: artifact_id.clone(),
                event_type: "artifact.module_grant_set".into(),
                payload: serde_json::to_value(payload)?,
                actor: Some(caller.actor().into()),
            },
        )
        .await?;
        db.commit_content(tx).await?;
        return Ok(json!({ "status": "granted", "artifact_id": artifact_id,
            "previous_seq": previous_seq }));
    }
    let rows = sqlx::query(
        "SELECT subject_kind,subject_record_id,subject_event_id,source_sha256,capability,scope,event_seq
           FROM artifact_module_grants WHERE artifact_id=?
          ORDER BY subject_kind,subject_event_id,capability,scope_sha256",
    ).bind(&artifact_id).fetch_all(db.write_pool()).await?;
    let mut grants = Vec::new();
    for row in rows {
        let subject_record_id = row.get::<String, _>("subject_record_id");
        if !can_record(&db, &caller, &subject_record_id, Capability::View).await? {
            continue;
        }
        grants.push(json!({
            "subject_kind": row.get::<String,_>("subject_kind"),
            "subject_record_id": subject_record_id,
            "subject_event_id": row.get::<String,_>("subject_event_id"),
            "source_sha256": row.get::<String,_>("source_sha256"),
            "capability": row.get::<String,_>("capability"),
            "scope": serde_json::from_str::<Value>(&row.get::<String,_>("scope")).unwrap_or(Value::Null),
            "event_seq": row.get::<i64,_>("event_seq"),
        }));
    }
    let _permit = mdx::try_admit().map_err(|failure| mdx_v2_engine_error(&artifact_id, failure))?;
    let mut snapshot = db.write_pool().begin().await?;
    let (artifact_source_event_id, artifact_source) =
        latest_body_source_in(&mut snapshot, &artifact_id).await?;
    let artifact_source_sha256 = mdx::sha256_hex(artifact_source.as_bytes());
    let source_descriptor_text: String = sqlx::query_scalar(
        "SELECT descriptor FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=? AND source_sha256=?",
    )
    .bind(&artifact_id)
    .bind(&artifact_source_event_id)
    .bind(&artifact_source_sha256)
    .fetch_optional(&mut *snapshot)
    .await?
    .ok_or_else(|| Error::engine("artifact grant-read source attestation is missing"))?;
    let source_descriptor: Value = serde_json::from_str(&source_descriptor_text)?;
    if source_descriptor.get("runtime").and_then(Value::as_str) == Some(HTML_RUNTIME) {
        let manifest =
            crate::artifact_html::validate_cached(&artifact_source).map_err(|failure| {
                Error::engine(format!(
                    "native.html.v1 grant-read source is invalid: {} [{}]",
                    failure.message, failure.code
                ))
            })?;
        if !manifest.named_inputs_declared {
            return Ok(json!({ "status": "ok", "artifact_id": artifact_id,
                "subjects": [{
                    "subject_kind": "artifact_source",
                    "subject_record_id": artifact_id,
                    "subject_event_id": artifact_source_event_id,
                    "source_sha256": artifact_source_sha256,
                    "requests": Vec::<Value>::new(),
                }], "grants": grants }));
        }
        return Ok(json!({ "status": "ok", "artifact_id": artifact_id,
            "subjects": [{
                "subject_kind": "artifact_source",
                "subject_record_id": artifact_id,
                "subject_event_id": artifact_source_event_id,
                "source_sha256": artifact_source_sha256,
                "requests": manifest.capability_requests,
            }], "grants": grants }));
    }
    let parse_source = artifact_source.clone();
    let artifact_parsed =
        tokio::task::spawn_blocking(move || mdx_v2::parse_artifact(&parse_source))
            .await
            .map_err(|_| Error::engine("native.mdx.v2 grant-read worker terminated unexpectedly"))?
            .map_err(|failure| mdx_v2_engine_error(&artifact_id, failure))?;
    let artifact_manifest = match &artifact_parsed.manifest {
        mdx_v2::Manifest::Artifact(manifest) => manifest,
        _ => unreachable!("artifact parser returns artifact manifest"),
    };
    let closure = resolve_closure_in(
        &mut snapshot,
        &artifact_parsed,
        caller.hosting_principal().unwrap_or("local"),
    )
    .await
    .map_err(|failure| mdx_v2_engine_error(&artifact_id, failure))?;
    let mut subjects = vec![json!({
        "subject_kind": "artifact_source",
        "subject_record_id": artifact_id,
        "subject_event_id": artifact_source_event_id,
        "source_sha256": mdx::sha256_hex(artifact_source.as_bytes()),
        "requests": artifact_manifest.capability_requests,
    })];
    for release in closure.values() {
        if !can_record(
            &db,
            &caller,
            &release.address.module_record_id,
            Capability::View,
        )
        .await?
        {
            continue;
        }
        subjects.push(json!({
            "subject_kind": "module_release",
            "subject_record_id": release.address.module_record_id,
            "subject_event_id": release.address.publication_event_id,
            "source_sha256": release.address.source_sha256,
            "requests": release.parsed.manifest.capability_requests(),
        }));
    }
    subjects.sort_by_key(|subject| {
        format!(
            "{}:{}",
            subject["subject_kind"].as_str().unwrap_or(""),
            subject["subject_event_id"].as_str().unwrap_or("")
        )
    });
    Ok(json!({ "status": "ok", "artifact_id": artifact_id,
        "subjects": subjects, "grants": grants,
        "verification": verification_state(mdx_v2::RUNTIME_ID) }))
}

pub(super) fn grant_key(
    publication_event_id: &str,
    capability: &str,
    module_port: &str,
    artifact_port: &str,
) -> String {
    let scope = json!({ "module_port": module_port, "artifact_port": artifact_port });
    grant_key_for_scope(publication_event_id, capability, &scope)
}

pub(super) fn grant_key_for_scope(
    publication_event_id: &str,
    capability: &str,
    scope: &Value,
) -> String {
    format!(
        "{publication_event_id}:{capability}:{}",
        mdx::sha256_hex(&mdx_v2::canonical_json_bytes(scope))
    )
}
