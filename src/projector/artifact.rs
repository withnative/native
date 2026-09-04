use super::*;

pub(super) async fn project_artifact_source_attested(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactSourceAttestedPayload = parse_payload(event)?;
    crate::mcp::tools::artifacts::verify_artifact_source_for_projection(
        conn,
        &event.record_id,
        &event.id,
        event.local_seq,
        &payload,
    )
    .await?;
    let source_event_id = payload.artifact_source["source_event_id"]
        .as_str()
        .expect("verified artifact source event id");
    let source_sha256 = payload.artifact_source["source_sha256"]
        .as_str()
        .expect("verified artifact source digest");
    sqlx::query(
        "INSERT INTO artifact_source_attestations
           (attestation_event_id,artifact_id,source_event_id,source_sha256,descriptor,attestation_sha256,event_seq,created_at)
         VALUES(?,?,?,?,?,?,?,?)",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(source_event_id)
    .bind(source_sha256)
    .bind(serde_json::to_string(&payload.artifact_source)?)
    .bind(&payload.attestation_sha256)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_module_release_published(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: ModuleReleasePublishedPayload = parse_payload(event)?;
    let core = payload
        .release_core
        .as_object()
        .ok_or_else(|| Error::engine("module release_core must be an object"))?;
    let string = |key: &str| -> Result<&str> {
        core.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| Error::engine(format!("module release_core.{key} must be a string")))
    };
    if string("schema")? != "native.module-release.v1"
        || string("publication_event_id")? != event.id
        || string("module_record_id")? != event.record_id
    {
        return Err(Error::engine(
            "module publication event envelope does not match release_core identity",
        ));
    }
    let source_event_id = string("source_event_id")?;
    let source_sha256 = string("source_sha256")?;
    let closure_sha256 = string("dependency_closure_sha256")?;
    if !valid_sha256(&payload.release_sha256)
        || !valid_sha256(source_sha256)
        || !valid_sha256(closure_sha256)
    {
        return Err(Error::engine(
            "module release digests must be 64 hex characters",
        ));
    }
    let source_row = sqlx::query(
        "SELECT type,record_id,seq,json_extract(payload,'$.body') AS source
           FROM content_events WHERE id=?",
    )
    .bind(source_event_id)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("module release source event does not exist"))?;
    let source_type: String = source_row.try_get("type")?;
    let source_record_id: String = source_row.try_get("record_id")?;
    let source_seq: i64 = source_row.try_get("seq")?;
    let source: Option<String> = source_row.try_get("source")?;
    if !matches!(
        source_type.as_str(),
        "record.created" | "record.updated" | "receipt.committed.v1"
    ) || source_record_id != event.record_id
        || source_seq >= event.local_seq
    {
        return Err(Error::engine(
            "module release source event identity or ordering is invalid",
        ));
    }
    let source = source.ok_or_else(|| Error::engine("module release source body is missing"))?;
    let governed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records r
           JOIN facet_values f ON f.record_id=r.id AND f.key='runtime'
          WHERE r.id=? AND r.deleted_at IS NULL AND r.type='Program' AND r.kind='module'
            AND f.value='native.mdx.v2'
            AND f.vocab_ref IN ('voc:artifact-runtime','rec:voc:artifact-runtime'))",
    )
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if !governed {
        return Err(Error::engine(
            "module release subject is not a live native.mdx.v2 Program kind:module",
        ));
    }
    crate::mcp::tools::artifacts::verify_mdx_release_for_projection(
        conn,
        event.local_seq,
        &event.id,
        &event.record_id,
        source_event_id,
        &source,
        &payload.release_core,
        &payload.release_sha256,
    )
    .await?;
    sqlx::query(
        "INSERT INTO module_releases
           (publication_event_id,module_record_id,source_event_id,source_sha256,release_sha256,
            dependency_closure_sha256,descriptor,status,local_event_seq,status_event_seq,published_at)
         VALUES (?,?,?,?,?,?,?,'published',?,?,?)",
    )
    .bind(&event.id)
    .bind(&event.record_id)
    .bind(source_event_id)
    .bind(source_sha256)
    .bind(&payload.release_sha256)
    .bind(closure_sha256)
    .bind(serde_json::to_string(&payload.release_core)?)
    .bind(event.local_seq)
    .bind(event.local_seq)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    let imports = core
        .get("imports")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::engine("module release_core.imports must be an array"))?;
    for (ordinal, import) in imports.iter().enumerate() {
        let import = import
            .as_object()
            .ok_or_else(|| Error::engine("module release import must be an object"))?;
        let get = |key: &str| -> Result<&str> {
            import.get(key).and_then(Value::as_str).ok_or_else(|| {
                Error::engine(format!("module release import.{key} must be a string"))
            })
        };
        sqlx::query(
            "INSERT INTO module_release_imports
               (consumer_publication_event_id,ordinal,specifier,dependency_module_record_id,
                dependency_publication_event_id,dependency_source_sha256,names,source_range,input_map)
             VALUES (?,?,?,?,?,?,?,?,?)",
        )
        .bind(&event.id)
        .bind(ordinal as i64)
        .bind(get("specifier")?)
        .bind(get("module_record_id")?)
        .bind(get("publication_event_id")?)
        .bind(get("source_sha256")?)
        .bind(serde_json::to_string(import.get("names").unwrap_or(&json!([])))?)
        .bind(serde_json::to_string(import.get("source_range").unwrap_or(&json!({})))?)
        .bind(serde_json::to_string(import.get("input_map").unwrap_or(&json!({})))?)
        .execute(&mut *conn)
        .await?;
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_module_release_status(
    conn: &mut SqliteConnection,
    event: &EventRow,
    status: &str,
) -> Result<()> {
    assert_record_live(conn, &event.record_id, &event.event_type).await?;
    let payload: ModuleReleaseStatusPayload = parse_payload(event)?;
    if status == "withdrawn" && payload.replacement.is_some() {
        return Err(Error::engine(
            "module withdrawal must not name a replacement release",
        ));
    }
    if let Some(replacement_id) = payload.replacement.as_deref() {
        let parsed = uuid::Uuid::parse_str(replacement_id)
            .map_err(|_| Error::engine("module replacement must be a canonical event UUID"))?;
        if parsed.hyphenated().to_string() != replacement_id
            || replacement_id == payload.publication_event_id
        {
            return Err(Error::engine(
                "module replacement must be a different canonical lowercase event UUID",
            ));
        }
        let rows = sqlx::query(
            "SELECT publication_event_id,module_record_id,status,descriptor FROM module_releases
              WHERE publication_event_id IN (?,?) ORDER BY publication_event_id",
        )
        .bind(&payload.publication_event_id)
        .bind(replacement_id)
        .fetch_all(&mut *conn)
        .await?;
        if rows.len() != 2 {
            return Err(Error::engine("module replacement release does not exist"));
        }
        let mut descriptors = std::collections::BTreeMap::new();
        for row in rows {
            let id: String = row.try_get("publication_event_id")?;
            let module_id: String = row.try_get("module_record_id")?;
            let release_status: String = row.try_get("status")?;
            let descriptor: Value = serde_json::from_str(&row.try_get::<String, _>("descriptor")?)?;
            descriptors.insert(id, (module_id, release_status, descriptor));
        }
        let current = descriptors
            .get(&payload.publication_event_id)
            .ok_or_else(|| Error::engine("module replacement source release is missing"))?;
        let replacement = descriptors
            .get(replacement_id)
            .ok_or_else(|| Error::engine("module replacement target release is missing"))?;
        if current.0 != event.record_id
            || replacement.0 != event.record_id
            || replacement.1 != "published"
            || !["runtime", "inputs", "exports", "capability_requests"]
                .into_iter()
                .all(|field| current.2.get(field) == replacement.2.get(field))
        {
            return Err(Error::engine(
                "module replacement is not an exact compatible published release of the same module",
            ));
        }
    }
    let allowed_status = if status == "deprecated" {
        "status='published'"
    } else {
        "status IN ('published','deprecated')"
    };
    let changed = sqlx::query(&format!(
        "UPDATE module_releases SET status=?,replacement=?,status_event_seq=?
          WHERE publication_event_id=? AND module_record_id=? AND status_event_seq=? AND {allowed_status}"
    ))
    .bind(status)
    .bind(payload.replacement)
    .bind(event.local_seq)
    .bind(payload.publication_event_id)
    .bind(&event.record_id)
    .bind(payload.expected_status_event_seq)
    .execute(&mut *conn)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine("module release status target does not exist"));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_artifact_input_bound(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactInputBoundPayload = parse_payload(event)?;
    if payload.artifact_id != event.record_id {
        return Err(Error::engine("artifact input event envelope mismatch"));
    }
    assert_v2_artifact(conn, &payload.artifact_id, &event.event_type).await?;
    assert_governed_collection(conn, &payload.collection_id, &event.event_type).await?;
    if payload.port_name == "default" || !valid_port_name(&payload.port_name) {
        return Err(Error::engine("artifact input port is invalid or reserved"));
    }
    crate::mcp::tools::artifacts::verify_artifact_input_for_projection(
        conn,
        &payload,
        event.local_seq,
    )
    .await?;
    sqlx::query(
        "INSERT INTO artifact_inputs
           (artifact_id,port_name,collection_id,artifact_source_attestation_event_id,
            artifact_source_event_id,artifact_source_sha256,event_seq)
         VALUES(?,?,?,?,?,?,?)
         ON CONFLICT(artifact_id,port_name) DO UPDATE SET
           collection_id=excluded.collection_id,
           artifact_source_attestation_event_id=excluded.artifact_source_attestation_event_id,
           artifact_source_event_id=excluded.artifact_source_event_id,
           artifact_source_sha256=excluded.artifact_source_sha256,
           event_seq=excluded.event_seq",
    )
    .bind(&payload.artifact_id)
    .bind(&payload.port_name)
    .bind(&payload.collection_id)
    .bind(&payload.artifact_source_attestation_event_id)
    .bind(&payload.artifact_source_event_id)
    .bind(&payload.artifact_source_sha256)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

struct CarrySourceIdentity<'a> {
    attestation_event_id: &'a str,
    source_event_id: &'a str,
    declaration_surface_sha256: &'a str,
}

async fn verified_equal_declaration_surfaces(
    conn: &mut SqliteConnection,
    artifact_id: &str,
    old: CarrySourceIdentity<'_>,
    new: CarrySourceIdentity<'_>,
    event_seq: i64,
) -> Result<()> {
    let rows = sqlx::query(
        "SELECT attestation_event_id,source_event_id,descriptor,event_seq FROM artifact_source_attestations
          WHERE artifact_id=? AND attestation_event_id IN (?,?)",
    )
    .bind(artifact_id)
    .bind(old.attestation_event_id)
    .bind(new.attestation_event_id)
    .fetch_all(&mut *conn)
    .await?;
    if rows.len() != 2 {
        return Err(Error::engine(
            "artifact carry source attestations are missing",
        ));
    }
    let mut attestations = std::collections::BTreeMap::new();
    for row in rows {
        if row.try_get::<i64, _>("event_seq")? >= event_seq {
            return Err(Error::engine(
                "artifact carry source attestation ordering is invalid",
            ));
        }
        let id: String = row.try_get("attestation_event_id")?;
        let descriptor: Value = serde_json::from_str(&row.try_get::<String, _>("descriptor")?)?;
        attestations.insert(
            id,
            (
                row.try_get::<String, _>("source_event_id")?,
                crate::mcp::tools::artifacts::declaration_surface_sha256(&descriptor)?,
            ),
        );
    }
    if attestations
        .get(old.attestation_event_id)
        .map(|(source, _)| source.as_str())
        != Some(old.source_event_id)
        || attestations
            .get(new.attestation_event_id)
            .map(|(source, _)| source.as_str())
            != Some(new.source_event_id)
        || attestations
            .get(old.attestation_event_id)
            .map(|(_, digest)| digest.as_str())
            != Some(old.declaration_surface_sha256)
        || attestations
            .get(new.attestation_event_id)
            .map(|(_, digest)| digest.as_str())
            != Some(new.declaration_surface_sha256)
        || old.declaration_surface_sha256 != new.declaration_surface_sha256
    {
        return Err(Error::engine("artifact carry declaration surface changed"));
    }
    let revisions = sqlx::query_scalar::<_, String>(
        "SELECT id FROM content_events WHERE record_id=? AND seq < ?
          AND type IN ('record.created','record.updated','receipt.committed.v1')
          AND json_type(payload,'$.body') IS NOT NULL ORDER BY seq DESC LIMIT 2",
    )
    .bind(artifact_id)
    .bind(event_seq)
    .fetch_all(&mut *conn)
    .await?;
    if revisions.as_slice() != [new.source_event_id, old.source_event_id] {
        return Err(Error::engine(
            "artifact carry source revisions are not adjacent",
        ));
    }
    Ok(())
}

pub(super) async fn project_artifact_input_carried(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactInputCarriedPayload = parse_payload(event)?;
    let binding = &payload.binding;
    if binding.artifact_id != event.record_id {
        return Err(Error::engine(
            "artifact input carry event envelope mismatch",
        ));
    }
    let predecessor = sqlx::query(
        "SELECT collection_id,artifact_source_attestation_event_id,artifact_source_event_id,
                artifact_source_sha256,event_seq
           FROM artifact_inputs WHERE artifact_id=? AND port_name=?",
    )
    .bind(&binding.artifact_id)
    .bind(&binding.port_name)
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("artifact input carry predecessor is not active"))?;
    if predecessor.try_get::<String, _>("collection_id")? != binding.collection_id
        || predecessor.try_get::<String, _>("artifact_source_attestation_event_id")?
            != payload.predecessor_source_attestation_event_id
        || predecessor.try_get::<String, _>("artifact_source_event_id")?
            != payload.predecessor_source_event_id
        || predecessor.try_get::<String, _>("artifact_source_sha256")?
            != payload.predecessor_source_sha256
        || predecessor.try_get::<i64, _>("event_seq")? != payload.predecessor_binding_event_seq
    {
        return Err(Error::engine(
            "artifact input carry predecessor does not match active state",
        ));
    }
    verified_equal_declaration_surfaces(
        conn,
        &binding.artifact_id,
        CarrySourceIdentity {
            attestation_event_id: &payload.predecessor_source_attestation_event_id,
            source_event_id: &payload.predecessor_source_event_id,
            declaration_surface_sha256: &payload.old_declaration_surface_sha256,
        },
        CarrySourceIdentity {
            attestation_event_id: &binding.artifact_source_attestation_event_id,
            source_event_id: &binding.artifact_source_event_id,
            declaration_surface_sha256: &payload.new_declaration_surface_sha256,
        },
        event.local_seq,
    )
    .await?;
    assert_governed_collection(conn, &binding.collection_id, &event.event_type).await?;
    crate::mcp::tools::artifacts::verify_artifact_input_for_projection(
        conn,
        binding,
        event.local_seq,
    )
    .await?;
    let changed = sqlx::query(
        "UPDATE artifact_inputs SET artifact_source_attestation_event_id=?,artifact_source_event_id=?,
                artifact_source_sha256=?,event_seq=?
          WHERE artifact_id=? AND port_name=? AND event_seq=?",
    )
    .bind(&binding.artifact_source_attestation_event_id)
    .bind(&binding.artifact_source_event_id)
    .bind(&binding.artifact_source_sha256)
    .bind(event.local_seq)
    .bind(&binding.artifact_id)
    .bind(&binding.port_name)
    .bind(payload.predecessor_binding_event_seq)
    .execute(&mut *conn)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine("artifact input carry predecessor changed"));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_artifact_input_unbound(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactInputUnboundPayload = parse_payload(event)?;
    if payload.artifact_id != event.record_id {
        return Err(Error::engine("artifact input event envelope mismatch"));
    }
    assert_v2_artifact(conn, &payload.artifact_id, &event.event_type).await?;
    if payload.port_name == "default" || !valid_port_name(&payload.port_name) {
        return Err(Error::engine("artifact input port is invalid or reserved"));
    }
    let changed = sqlx::query("DELETE FROM artifact_inputs WHERE artifact_id=? AND port_name=?")
        .bind(&payload.artifact_id)
        .bind(&payload.port_name)
        .execute(&mut *conn)
        .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine("artifact input binding does not exist"));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_artifact_module_grant_set(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactModuleGrantPayload = parse_payload(event)?;
    if payload.artifact_id != event.record_id {
        return Err(Error::engine(
            "artifact module grant event envelope mismatch",
        ));
    }
    if !crate::mcp::tools::artifacts::is_supported_grant_capability(&payload.capability)
        || !valid_sha256(&payload.source_sha256)
        || !valid_sha256(&payload.scope_sha256)
        || crate::mcp::tools::artifacts::mdx_sha256_for_projection(&payload.scope)
            != payload.scope_sha256
    {
        return Err(Error::engine("artifact module grant contract is invalid"));
    }
    crate::mcp::tools::artifacts::verify_mdx_grant_for_projection(conn, &payload, event.local_seq)
        .await?;
    let attestation = payload
        .attestation
        .as_ref()
        .expect("verified grant set has an attestation");
    sqlx::query(
        "INSERT INTO artifact_module_grants
           (artifact_id,subject_kind,subject_record_id,subject_event_id,source_sha256,
            artifact_source_attestation_event_id,artifact_source_event_id,artifact_source_sha256,
            capability,scope_sha256,scope,event_seq)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT(artifact_id,subject_kind,subject_record_id,subject_event_id,capability,scope_sha256)
         DO UPDATE SET
           artifact_source_attestation_event_id=excluded.artifact_source_attestation_event_id,
           artifact_source_event_id=excluded.artifact_source_event_id,
           artifact_source_sha256=excluded.artifact_source_sha256,
           event_seq=excluded.event_seq",
    )
    .bind(&payload.artifact_id)
    .bind(&payload.subject_kind)
    .bind(&payload.subject_record_id)
    .bind(&payload.subject_event_id)
    .bind(&payload.source_sha256)
    .bind(attestation["artifact_source_attestation_event_id"].as_str())
    .bind(attestation["artifact_source_event_id"].as_str())
    .bind(attestation["artifact_source_sha256"].as_str())
    .bind(&payload.capability)
    .bind(&payload.scope_sha256)
    .bind(serde_json::to_string(&payload.scope)?)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_artifact_module_grant_carried(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactModuleGrantCarriedPayload = parse_payload(event)?;
    let old = &payload.predecessor;
    let new = &payload.grant;
    if old.artifact_id != event.record_id
        || new.artifact_id != event.record_id
        || !crate::mcp::tools::artifacts::is_supported_grant_capability(&old.capability)
        || new.capability != old.capability
        || new.scope != old.scope
        || new.scope_sha256 != old.scope_sha256
        || !valid_sha256(&old.source_sha256)
        || !valid_sha256(&new.source_sha256)
        || !valid_sha256(&old.scope_sha256)
        || crate::mcp::tools::artifacts::mdx_sha256_for_projection(&old.scope) != old.scope_sha256
        || crate::mcp::tools::artifacts::mdx_sha256_for_projection(&new.scope) != new.scope_sha256
        || old.attestation.is_some()
        || old.attestation_sha256.is_some()
    {
        return Err(Error::engine(
            "artifact module grant carry broadens authority",
        ));
    }
    let predecessor_active: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM artifact_module_grants
          WHERE artifact_id=? AND subject_kind=? AND subject_record_id=? AND subject_event_id=?
            AND source_sha256=? AND capability=? AND scope_sha256=? AND event_seq=?
            AND artifact_source_attestation_event_id=? AND artifact_source_event_id=?
            AND artifact_source_sha256=?)",
    )
    .bind(&old.artifact_id)
    .bind(&old.subject_kind)
    .bind(&old.subject_record_id)
    .bind(&old.subject_event_id)
    .bind(&old.source_sha256)
    .bind(&old.capability)
    .bind(&old.scope_sha256)
    .bind(payload.predecessor_grant_event_seq)
    .bind(&payload.predecessor_source_attestation_event_id)
    .bind(&payload.predecessor_source_event_id)
    .bind(&payload.predecessor_source_sha256)
    .fetch_one(&mut *conn)
    .await?;
    if !predecessor_active {
        return Err(Error::engine(
            "artifact module grant carry predecessor is not active",
        ));
    }
    let subject_compatible = if old.subject_kind == "module_release" {
        new.subject_kind == old.subject_kind
            && new.subject_record_id == old.subject_record_id
            && new.subject_event_id == old.subject_event_id
            && new.source_sha256 == old.source_sha256
    } else if old.subject_kind == "artifact_source" {
        new.subject_kind == old.subject_kind
            && old.subject_record_id == old.artifact_id
            && new.subject_record_id == new.artifact_id
            && old.subject_event_id == payload.predecessor_source_event_id
            && old.source_sha256 == payload.predecessor_source_sha256
            && new.subject_event_id
                == new
                    .attestation
                    .as_ref()
                    .and_then(|a| a["artifact_source_event_id"].as_str())
                    .unwrap_or("")
            && new.source_sha256
                == new
                    .attestation
                    .as_ref()
                    .and_then(|a| a["artifact_source_sha256"].as_str())
                    .unwrap_or("")
    } else {
        false
    };
    if !subject_compatible {
        return Err(Error::engine(
            "artifact module grant carry subject changed incompatibly",
        ));
    }
    let new_attestation_event_id = new
        .attestation
        .as_ref()
        .and_then(|attestation| attestation["artifact_source_attestation_event_id"].as_str())
        .ok_or_else(|| Error::engine("artifact module grant carry attestation is missing"))?;
    verified_equal_declaration_surfaces(
        conn,
        &new.artifact_id,
        CarrySourceIdentity {
            attestation_event_id: &payload.predecessor_source_attestation_event_id,
            source_event_id: &payload.predecessor_source_event_id,
            declaration_surface_sha256: &payload.old_declaration_surface_sha256,
        },
        CarrySourceIdentity {
            attestation_event_id: new_attestation_event_id,
            source_event_id: new
                .attestation
                .as_ref()
                .and_then(|attestation| attestation["artifact_source_event_id"].as_str())
                .expect("new carry attestation identity checked above"),
            declaration_surface_sha256: &payload.new_declaration_surface_sha256,
        },
        event.local_seq,
    )
    .await?;
    crate::mcp::tools::artifacts::verify_mdx_grant_for_projection(conn, new, event.local_seq)
        .await?;
    let removed = sqlx::query(
        "DELETE FROM artifact_module_grants
          WHERE artifact_id=? AND subject_kind=? AND subject_record_id=? AND subject_event_id=?
            AND source_sha256=? AND capability=? AND scope_sha256=? AND event_seq=?",
    )
    .bind(&old.artifact_id)
    .bind(&old.subject_kind)
    .bind(&old.subject_record_id)
    .bind(&old.subject_event_id)
    .bind(&old.source_sha256)
    .bind(&old.capability)
    .bind(&old.scope_sha256)
    .bind(payload.predecessor_grant_event_seq)
    .execute(&mut *conn)
    .await?;
    if removed.rows_affected() != 1 {
        return Err(Error::engine(
            "artifact module grant carry predecessor changed",
        ));
    }
    let attestation = new
        .attestation
        .as_ref()
        .expect("verified carry attestation");
    sqlx::query(
        "INSERT INTO artifact_module_grants
           (artifact_id,subject_kind,subject_record_id,subject_event_id,source_sha256,
            artifact_source_attestation_event_id,artifact_source_event_id,artifact_source_sha256,
            capability,scope_sha256,scope,event_seq) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
    )
    .bind(&new.artifact_id)
    .bind(&new.subject_kind)
    .bind(&new.subject_record_id)
    .bind(&new.subject_event_id)
    .bind(&new.source_sha256)
    .bind(attestation["artifact_source_attestation_event_id"].as_str())
    .bind(attestation["artifact_source_event_id"].as_str())
    .bind(attestation["artifact_source_sha256"].as_str())
    .bind(&new.capability)
    .bind(&new.scope_sha256)
    .bind(serde_json::to_string(&new.scope)?)
    .bind(event.local_seq)
    .execute(&mut *conn)
    .await?;
    touch(conn, &event.record_id, &event.created_at).await
}

pub(super) async fn project_artifact_module_grant_unset(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let payload: ArtifactModuleGrantPayload = parse_payload(event)?;
    if payload.artifact_id != event.record_id {
        return Err(Error::engine(
            "artifact module grant event envelope mismatch",
        ));
    }
    assert_v2_artifact(conn, &payload.artifact_id, &event.event_type).await?;
    if !valid_sha256(&payload.source_sha256)
        || !valid_sha256(&payload.scope_sha256)
        || crate::mcp::tools::artifacts::mdx_sha256_for_projection(&payload.scope)
            != payload.scope_sha256
    {
        return Err(Error::engine("artifact module grant contract is invalid"));
    }
    let changed = sqlx::query(
        "DELETE FROM artifact_module_grants
          WHERE artifact_id=? AND subject_kind=? AND subject_record_id=? AND subject_event_id=?
            AND source_sha256=? AND capability=? AND scope_sha256=?",
    )
    .bind(&payload.artifact_id)
    .bind(&payload.subject_kind)
    .bind(&payload.subject_record_id)
    .bind(&payload.subject_event_id)
    .bind(&payload.source_sha256)
    .bind(&payload.capability)
    .bind(&payload.scope_sha256)
    .execute(&mut *conn)
    .await?;
    if changed.rows_affected() != 1 {
        return Err(Error::engine("artifact module grant does not exist"));
    }
    touch(conn, &event.record_id, &event.created_at).await
}

fn valid_port_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

async fn assert_v2_artifact(conn: &mut SqliteConnection, id: &str, event_type: &str) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records r
           JOIN facet_values f ON f.record_id=r.id AND f.key='runtime'
          WHERE r.id=? AND r.deleted_at IS NULL AND r.type='Document' AND r.kind='artifact'
            AND f.value IN ('native.mdx.v2','native.html.v1'))",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    if !valid {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: {id} is not a live named-input artifact"
        )));
    }
    Ok(())
}

async fn assert_governed_collection(
    conn: &mut SqliteConnection,
    id: &str,
    event_type: &str,
) -> Result<()> {
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM records WHERE id=? AND deleted_at IS NULL
          AND type='Collection' AND kind IN ('query','selection','folder'))",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await?;
    if !valid {
        return Err(Error::engine(format!(
            "cannot apply {event_type}: {id} is not a live governed Collection"
        )));
    }
    Ok(())
}
