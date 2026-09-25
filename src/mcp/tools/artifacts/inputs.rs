//! Named artifact input binding governance.

use super::*;

/// Batch limit for the plural bind path. Mirrors
/// `ManageRecordPolicyArgs::SetMany` (`MAX_SET_MANY_ITEMS` in
/// `src/mcp/tools/policy.rs`): large enough that no legitimate authoring
/// batch hits it, small enough that one call cannot hold the write
/// transaction open over an unbounded event batch.
const MAX_BIND_MANY_ITEMS: usize = 100;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BindManyItemInput {
    port_name: String,
    collection_id: String,
}

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
    /// Bind between 1 and [`MAX_BIND_MANY_ITEMS`] ports atomically: every
    /// item validates before the first event appends, so one invalid item
    /// leaves the whole set unchanged.
    ///
    /// Mixed-batch reporting is deliberately coarse. Each returned binding
    /// carries its own `event_seq`, and an all-already-bound batch reports
    /// `unchanged`. But a batch where at least one port is newly bound
    /// reports `bound` for the whole batch, and the per-port entries do not
    /// say which ports were newly bound versus already bound to the same
    /// collection — both read back as the port's current row.
    BindMany {
        artifact_id: String,
        bindings: Vec<BindManyItemInput>,
    },
    Unbind {
        artifact_id: String,
        port_name: String,
        collection_id: String,
        event_seq: i64,
    },
}

fn validate_bind_many_count(bindings: &[BindManyItemInput]) -> Result<()> {
    const TOOL: &str = "manage_artifact_inputs";
    if bindings.is_empty() || bindings.len() > MAX_BIND_MANY_ITEMS {
        return Err(Error::engine(format!(
            "{TOOL}: bind_many bindings must contain between 1 and {MAX_BIND_MANY_ITEMS} entries"
        )));
    }
    Ok(())
}

/// Exact source identity shared by every binding in one write transaction.
///
/// Fetched once per call: every port in a batch pins the same artifact
/// source event, digest and attestation.
struct BindingAttestation {
    source_event_id: String,
    source_sha256: String,
    attestation_event_id: String,
    descriptor: Value,
}

async fn binding_attestation_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    artifact_id: &str,
) -> Result<BindingAttestation> {
    let (artifact_source_event_id, artifact_source) =
        latest_body_source_in(tx, artifact_id).await?;
    let artifact_source_sha256 = mdx::sha256_hex(artifact_source.as_bytes());
    let attestation = sqlx::query(
        "SELECT attestation_event_id,source_sha256,descriptor
           FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=?",
    )
    .bind(artifact_id)
    .bind(&artifact_source_event_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| {
        Error::engine("manage_artifact_inputs: exact artifact source attestation is missing")
    })?;
    if attestation.try_get::<String, _>("source_sha256")? != artifact_source_sha256 {
        return Err(Error::engine(
            "manage_artifact_inputs: artifact source attestation digest mismatch",
        ));
    }
    Ok(BindingAttestation {
        source_event_id: artifact_source_event_id,
        source_sha256: artifact_source_sha256,
        attestation_event_id: attestation.try_get("attestation_event_id")?,
        descriptor: serde_json::from_str(&attestation.try_get::<String, _>("descriptor")?)?,
    })
}

enum PreparedBinding {
    Unchanged {
        event_seq: i64,
    },
    // Boxed: the payload is at least 240 bytes against the 8-byte
    // `Unchanged` variant (`clippy::large_enum_variant`), and prepared
    // bindings are moved into a batch `Vec` before appending.
    New {
        payload: Box<ArtifactInputBoundPayload>,
    },
}

/// Attestation-independent prefix of one port's bind validation, in the exact
/// singular-bind precedence: port name, then authorization, then the governed
/// Collection check. Runs before the artifact source attestation is read so a
/// bad port or target reports itself rather than being shadowed by a missing
/// or mismatched attestation row.
async fn validate_binding_target_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    port_name: &str,
    collection_id: &str,
) -> Result<String> {
    const TOOL: &str = "manage_artifact_inputs";
    if port_name == "default" || !valid_port_name(port_name) {
        return Err(Error::engine(
            "manage_artifact_inputs: invalid or reserved port name",
        ));
    }
    require_record_in(tx, caller, TOOL, artifact_id, Capability::Edit).await?;
    require_record_in(tx, caller, TOOL, collection_id, Capability::View).await?;
    collection_kind_in(tx, collection_id).await?.ok_or_else(|| {
        Error::engine("manage_artifact_inputs: target must be a governed Collection")
    })
}

/// Attestation-dependent remainder of one port's bind validation: port
/// declaration, relation validation and the current-binding compare. Appends
/// nothing; the caller decides when the prepared payload is appended, which
/// is what makes the plural path atomic.
async fn finish_binding_in(
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    artifact_id: &str,
    port_name: &str,
    collection_id: &str,
    collection_kind: &str,
    attestation: &BindingAttestation,
) -> Result<PreparedBinding> {
    let port_declaration = attestation.descriptor["artifact_ports"]
        .get(port_name)
        .ok_or_else(|| {
            Error::engine("manage_artifact_inputs: artifact does not declare this port")
        })?
        .clone();
    let declaration: mdx_v2::InputDecl =
        serde_json::from_value(port_declaration.clone()).map_err(|_| {
            Error::engine("manage_artifact_inputs: attested port declaration is invalid")
        })?;
    validate_input_binding_relation_in(tx, collection_id, collection_kind, &declaration).await?;
    let current = sqlx::query(
        "SELECT collection_id,event_seq,artifact_source_attestation_event_id,
                artifact_source_event_id,artifact_source_sha256
           FROM artifact_inputs WHERE artifact_id=? AND port_name=?",
    )
    .bind(artifact_id)
    .bind(port_name)
    .fetch_optional(&mut **tx)
    .await?;
    if let Some(current) = current {
        let current_collection: String = current.try_get("collection_id")?;
        let exact_source = current.try_get::<String, _>("artifact_source_attestation_event_id")?
            == attestation.attestation_event_id
            && current.try_get::<String, _>("artifact_source_event_id")?
                == attestation.source_event_id
            && current.try_get::<String, _>("artifact_source_sha256")? == attestation.source_sha256;
        if current_collection == collection_id && exact_source {
            return Ok(PreparedBinding::Unchanged {
                event_seq: current.try_get("event_seq")?,
            });
        }
        if current_collection != collection_id {
            return Err(Error::engine(format!(
                "manage_artifact_inputs: port '{port_name}' changed or is already bound; re-read and explicitly unbind its exact current binding first"
            )));
        }
    }
    let mut payload = ArtifactInputBoundPayload {
        artifact_id: artifact_id.to_owned(),
        port_name: port_name.to_owned(),
        collection_id: collection_id.to_owned(),
        artifact_source_event_id: attestation.source_event_id.clone(),
        artifact_source_sha256: attestation.source_sha256.clone(),
        artifact_source_attestation_event_id: attestation.attestation_event_id.clone(),
        port_declaration,
        attestation_sha256: String::new(),
    };
    payload.attestation_sha256 = mdx_sha256_for_projection(&input_attestation_value(&payload));
    Ok(PreparedBinding::New {
        payload: Box::new(payload),
    })
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
        | ManageArtifactInputsArgs::BindMany { artifact_id, .. }
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
        ManageArtifactInputsArgs::BindMany { bindings, .. } => {
            validate_bind_many_count(bindings)?;
            require_record(&db, &caller, TOOL, &artifact_id, Capability::Edit).await?;
            for (index, item) in bindings.iter().enumerate() {
                require_record(&db, &caller, TOOL, &item.collection_id, Capability::View)
                    .await
                    .map_err(|error| {
                        Error::engine(format!("{TOOL}: bind_many item {index}: {error}"))
                    })?;
            }
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
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
            let collection_kind = validate_binding_target_in(
                &mut tx,
                &caller,
                &artifact_id,
                &port_name,
                &collection_id,
            )
            .await?;
            let attestation = binding_attestation_in(&mut tx, &artifact_id).await?;
            match finish_binding_in(
                &mut tx,
                &artifact_id,
                &port_name,
                &collection_id,
                &collection_kind,
                &attestation,
            )
            .await?
            {
                PreparedBinding::Unchanged { event_seq } => {
                    tx.rollback().await?;
                    return Ok(json!({
                        "status": "unchanged", "artifact_id": artifact_id,
                        "bindings": [{ "port_name": port_name,
                            "collection_id": collection_id,
                            "event_seq": event_seq }],
                    }));
                }
                PreparedBinding::New { payload } => {
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
                        &mut act_alloc,
                    )
                    .await?;
                    db.commit_content(tx).await?;
                    return Ok(json!({ "status": "bound", "artifact_id": artifact_id,
                        "previous_seq": previous_seq }));
                }
            }
        }
        ManageArtifactInputsArgs::BindMany { bindings, .. } => {
            validate_bind_many_count(&bindings)?;
            let mut seen = BTreeSet::new();
            for (index, item) in bindings.iter().enumerate() {
                if !seen.insert(item.port_name.clone()) {
                    return Err(Error::engine(format!(
                        "{TOOL}: bind_many item {index}: duplicate port '{}'",
                        item.port_name
                    )));
                }
            }
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            // One memo for the whole batch: every appended binding stamps the
            // same act, which is what makes the batch one atomic write rather
            // than N writes sharing a transaction.
            let mut act_alloc = crate::act::ActAllocation::new();
            require_record_in(&mut tx, &caller, TOOL, &artifact_id, Capability::Edit).await?;
            // Phase one: every item's port, authorization and governed
            // Collection checks first, in singular-bind precedence, before the
            // shared attestation is read.
            let mut targets = Vec::with_capacity(bindings.len());
            for (index, item) in bindings.iter().enumerate() {
                let collection_kind = validate_binding_target_in(
                    &mut tx,
                    &caller,
                    &artifact_id,
                    &item.port_name,
                    &item.collection_id,
                )
                .await
                .map_err(|error| {
                    Error::engine(format!("{TOOL}: bind_many item {index}: {error}"))
                })?;
                targets.push(collection_kind);
            }
            let attestation = binding_attestation_in(&mut tx, &artifact_id).await?;
            // Phase two: declaration, relation and current-binding checks.
            // Validate every item before the first event is appended. One
            // invalid item therefore leaves the entire requested set
            // unchanged; the transaction is dropped without committing.
            let mut prepared = Vec::with_capacity(bindings.len());
            debug_assert_eq!(targets.len(), bindings.len());
            for (index, (item, collection_kind)) in bindings.into_iter().zip(targets).enumerate() {
                let outcome = finish_binding_in(
                    &mut tx,
                    &artifact_id,
                    &item.port_name,
                    &item.collection_id,
                    &collection_kind,
                    &attestation,
                )
                .await
                .map_err(|error| {
                    Error::engine(format!("{TOOL}: bind_many item {index}: {error}"))
                })?;
                prepared.push((item.port_name, item.collection_id, outcome));
            }
            let previous_seq = previous_record_seq_in(&mut tx, &artifact_id).await?;
            let mut changed = false;
            for (_, _, outcome) in &prepared {
                if let PreparedBinding::New { payload } = outcome {
                    append_in(
                        &db,
                        &mut tx,
                        AppendSpec {
                            record_id: artifact_id.clone(),
                            event_type: "artifact.input_bound".into(),
                            payload: serde_json::to_value(payload)?,
                            actor: Some(caller.actor().into()),
                        },
                        &mut act_alloc,
                    )
                    .await?;
                    changed = true;
                }
            }
            if !changed {
                tx.rollback().await?;
                let bindings = prepared
                    .into_iter()
                    .map(|(port_name, collection_id, outcome)| {
                        let event_seq = match outcome {
                            PreparedBinding::Unchanged { event_seq } => event_seq,
                            PreparedBinding::New { .. } => {
                                unreachable!("unchanged batch holds no new bindings")
                            }
                        };
                        json!({
                            "port_name": port_name,
                            "collection_id": collection_id,
                            "event_seq": event_seq,
                        })
                    })
                    .collect::<Vec<_>>();
                return Ok(json!({
                    "status": "unchanged", "artifact_id": artifact_id,
                    "bindings": bindings,
                }));
            }
            let port_names = prepared
                .iter()
                .map(|(port_name, _, _)| port_name.clone())
                .collect::<Vec<_>>();
            let placeholders = port_names.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            let reread = format!(
                "SELECT port_name,collection_id,event_seq FROM artifact_inputs
                  WHERE artifact_id=? AND port_name IN ({placeholders})"
            );
            let mut bound = sqlx::query(&reread).bind(&artifact_id);
            for port_name in &port_names {
                bound = bound.bind(port_name);
            }
            let rows = bound.fetch_all(&mut *tx).await?;
            let mut by_port = HashMap::new();
            for row in rows {
                by_port.insert(
                    row.try_get::<String, _>("port_name")?,
                    (
                        row.try_get::<String, _>("collection_id")?,
                        row.try_get::<i64, _>("event_seq")?,
                    ),
                );
            }
            let bindings = prepared
                .into_iter()
                .map(|(port_name, _, _)| {
                    let (collection_id, event_seq) = by_port.remove(&port_name).ok_or_else(|| {
                        Error::engine(format!(
                            "{TOOL}: bind_many lost the '{port_name}' binding inside its own transaction"
                        ))
                    })?;
                    Ok(json!({
                        "port_name": port_name,
                        "collection_id": collection_id,
                        "event_seq": event_seq,
                    }))
                })
                .collect::<Result<Vec<_>>>()?;
            db.commit_content(tx).await?;
            return echo_act(
                json!({ "status": "bound", "artifact_id": artifact_id,
                "previous_seq": previous_seq, "bindings": bindings }),
                act_alloc.get(),
            );
        }
        ManageArtifactInputsArgs::Unbind {
            port_name,
            collection_id,
            event_seq,
            ..
        } => {
            let mut tx = crate::db::begin_write(db.write_pool()).await?;
            let mut act_alloc = crate::act::ActAllocation::new();
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
                &mut act_alloc,
            )
            .await?;
            db.commit_content(tx).await?;
            return echo_act(
                json!({ "status": "unbound", "artifact_id": artifact_id,
                "previous_seq": previous_seq }),
                act_alloc.get(),
            );
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
