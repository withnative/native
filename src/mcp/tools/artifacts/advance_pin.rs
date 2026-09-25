//! Atomic advance of one bound artifact port's pinned governed-SQL relation
//! version.
//!
//! A governed SQL relation can gain an additive column without changing any
//! query's output columns. A saved query and the artifact port that consumes it
//! each pin that relation's `semantic_version` independently, so when the
//! catalog advances the two pins can disagree. Repairing that by hand takes
//! four calls — re-pin the query, re-pin the port, rebind the port, re-grant
//! the `input.read` capability — and the third and fourth are only discoverable
//! from a warning emitted after the body edit has already dropped them.
//!
//! This operation performs all four as one authorized action. It accepts only
//! the version to advance to (and refuses any version but the current catalog
//! version), so "only the pin changed" is a property of the operation's input
//! shape rather than something inferred by diffing an arbitrary body edit.
//! The grant is deliberately re-issued as a fresh `artifact.module_grant_set`
//! event against the new exact source rather than transferred, so the audit
//! trail is preserved while the caller is not interrupted.

use super::*;

use crate::domain_transaction::{facet_set_spec, FacetWrite};
use crate::events::ArtifactInputCarriedPayload;
use crate::query::sql_contract::LOGICAL_RELATIONS;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdvanceArtifactPortPinArgs {
    pub(crate) artifact_id: String,
    pub(crate) port_name: String,
    #[serde(default)]
    pub(crate) relation_name: Option<String>,
    #[serde(default)]
    pub(crate) target_version: Option<u32>,
    #[serde(default)]
    pub(crate) if_body_digest: Option<String>,
    pub(crate) reason: String,
}

/// The current catalog contract for one semantic relation identity, if the
/// identity is a governed SQL logical relation at all.
fn catalog_relation(
    identity: &str,
) -> Option<&'static crate::query::sql_contract::QuerySqlRelationContract> {
    LOGICAL_RELATIONS
        .iter()
        .find(|relation| relation.identity == identity)
}

fn canonical_declaration(value: &Value) -> Vec<u8> {
    mdx_v2::canonical_json_bytes(value)
}

/// Parse one native.mdx.v2 artifact source into its validated manifest.
fn artifact_manifest(artifact_id: &str, source: &str) -> Result<mdx_v2::ArtifactManifest> {
    let parsed = mdx_v2::parse_artifact(source)
        .map_err(|failure| mdx_v2_engine_error(artifact_id, failure))?;
    match parsed.manifest {
        mdx_v2::Manifest::Artifact(manifest) => Ok(manifest),
        mdx_v2::Manifest::Module(_) => Err(Error::engine(format!(
            "advance_artifact_port_pin: {artifact_id} is not a native.mdx.v2 artifact"
        ))),
    }
}

/// The manifest's declared interactions as JSON. Interactions are authored in
/// the body but are not part of the compiler attestation, so the pin-only guard
/// cannot see them through the descriptor; it compares them from the parsed
/// manifests of the old and prospective bodies instead.
fn artifact_interactions(artifact_id: &str, source: &str) -> Result<Value> {
    Ok(serde_json::to_value(
        artifact_manifest(artifact_id, source)?.interactions,
    )?)
}

/// Render a replacement `nativeArtifact` declaration that differs from the
/// parsed source only in the named port/relation version pin.
///
/// The rewrite is confined to the exact `export const nativeArtifact = {...}`
/// span reported by the parser; every byte before that span and every byte
/// after it — imports, other exports, and all authored MDX/JSX, comments and
/// whitespace included — is copied through verbatim. The operation therefore
/// cannot reformat an author's body.
fn repinned_artifact_source(
    artifact_id: &str,
    source: &str,
    port_name: &str,
    relation_name: &str,
    target_version: u32,
) -> Result<String> {
    let parsed = mdx_v2::parse_artifact(source)
        .map_err(|failure| mdx_v2_engine_error(artifact_id, failure))?;
    let mut manifest = match parsed.manifest.clone() {
        mdx_v2::Manifest::Artifact(manifest) => manifest,
        mdx_v2::Manifest::Module(_) => {
            return Err(Error::engine(format!(
                "advance_artifact_port_pin: {artifact_id} is not a native.mdx.v2 artifact"
            )))
        }
    };
    let port = manifest.inputs.get_mut(port_name).ok_or_else(|| {
        Error::engine(format!(
            "advance_artifact_port_pin: artifact {artifact_id} does not declare port '{port_name}'"
        ))
    })?;
    let relation = port.relations.get_mut(relation_name).ok_or_else(|| {
        Error::engine(format!(
            "advance_artifact_port_pin: port '{port_name}' does not pin relation '{relation_name}'"
        ))
    })?;
    relation.semantic_version = target_version;
    let rendered = serde_json::to_string(&manifest)?;
    let range = parsed.export_ranges.get("nativeArtifact").ok_or_else(|| {
        Error::engine(format!(
            "advance_artifact_port_pin: artifact {artifact_id} has no inspectable nativeArtifact declaration"
        ))
    })?;
    let start = range["start"]["offset"]
        .as_u64()
        .ok_or_else(|| Error::engine("nativeArtifact declaration start offset is malformed"))?
        as usize;
    let end = range["end"]["offset"]
        .as_u64()
        .ok_or_else(|| Error::engine("nativeArtifact declaration end offset is malformed"))?
        as usize;
    if start > end
        || end > source.len()
        || !source.is_char_boundary(start)
        || !source.is_char_boundary(end)
    {
        return Err(Error::engine(
            "advance_artifact_port_pin: nativeArtifact declaration range is invalid",
        ));
    }
    let mut repinned = String::with_capacity(source.len() + rendered.len());
    repinned.push_str(&source[..start]);
    repinned.push_str("export const nativeArtifact = ");
    repinned.push_str(&rendered);
    repinned.push(';');
    repinned.push_str(&source[end..]);
    Ok(repinned)
}

/// Render a replacement inert HTML manifest that differs only in the named
/// relation version. The validator has already established that the document
/// contains exactly one live declaration. This raw-source pass additionally
/// requires exactly one script body whose JSON declares an HTML artifact, so
/// an ambiguous copy (for example in a comment) fails closed rather than
/// donating its byte offsets to the live declaration. Meta-based manifests do
/// not have an independently addressable JSON body and remain unsupported by
/// this pin-only operation.
fn repinned_html_source(
    artifact_id: &str,
    source: &str,
    port_name: &str,
    relation_name: &str,
    target_version: u32,
) -> Result<String> {
    let lower = source.to_ascii_lowercase();
    let mut cursor = 0usize;
    let mut candidates = Vec::new();
    while let Some(relative) = lower[cursor..].find("<script") {
        let tag_start = cursor + relative;
        let after_name = tag_start + "<script".len();
        match source.as_bytes().get(after_name) {
            Some(b' ') | Some(b'\t') | Some(b'\n') | Some(b'\r') | Some(b'>') => {}
            _ => {
                cursor = after_name;
                continue;
            }
        }
        let mut quote = None;
        let mut tag_end = None;
        for (offset, byte) in source.as_bytes()[after_name..].iter().copied().enumerate() {
            match (quote, byte) {
                (None, b'\'' | b'"') => quote = Some(byte),
                (Some(expected), actual) if expected == actual => quote = None,
                (None, b'>') => {
                    tag_end = Some(after_name + offset + 1);
                    break;
                }
                _ => {}
            }
        }
        let Some(body_start) = tag_end else {
            break;
        };
        let Some(close_relative) = lower[body_start..].find("</script") else {
            break;
        };
        let body_end = body_start + close_relative;
        if let Ok(value) = serde_json::from_str::<Value>(&source[body_start..body_end]) {
            let schema = value.get("schema").and_then(Value::as_str);
            if matches!(
                schema,
                Some(crate::artifact_html::MANIFEST_SCHEMA)
                    | Some(crate::artifact_html::INTERACTIVE_MANIFEST_SCHEMA)
            ) {
                candidates.push((body_start, body_end, value));
            }
        }
        cursor = body_end + "</script".len();
    }
    let [(start, end, mut manifest)] = candidates.try_into().map_err(|items: Vec<_>| {
        Error::engine(format!(
            "advance_artifact_port_pin: native.html.v1 artifact {artifact_id} must contain exactly one unambiguous script manifest; found {} (meta manifests require update_record)",
            items.len()
        ))
    })?;
    let relation = manifest
        .get_mut("inputs")
        .and_then(Value::as_object_mut)
        .and_then(|inputs| inputs.get_mut(port_name))
        .and_then(Value::as_object_mut)
        .and_then(|port| port.get_mut("relations"))
        .and_then(Value::as_object_mut)
        .and_then(|relations| relations.get_mut(relation_name))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            Error::engine(format!(
                "advance_artifact_port_pin: port '{port_name}' does not pin relation '{relation_name}'"
            ))
        })?;
    relation.insert("semantic_version".into(), json!(target_version));
    let rendered = serde_json::to_string(&manifest)?;
    let mut repinned = String::with_capacity(source.len() + rendered.len());
    repinned.push_str(&source[..start]);
    repinned.push_str(&rendered);
    repinned.push_str(&source[end..]);
    Ok(repinned)
}

/// The artifact must have changed, and the change must be exactly one version
/// pin.
///
/// `old_interactions`/`new_interactions` are the parsed declarations'
/// `interactions`, which the compiler attestation does not carry. Comparing
/// them here keeps the guard as wide as its claim: no manifest field may move
/// except the named relation's version.
#[allow(clippy::too_many_arguments)]
fn assert_pin_only_change(
    artifact_id: &str,
    port_name: &str,
    relation_name: &str,
    target_version: u32,
    old_descriptor: &Value,
    new_compiler: &Value,
    old_interactions: &Value,
    new_interactions: &Value,
) -> Result<()> {
    if old_interactions != new_interactions {
        return Err(Error::engine(format!(
            "advance_artifact_port_pin: artifact {artifact_id} interactions would change; that is a declaration change and must use update_record"
        )));
    }
    let old_ports = old_descriptor
        .get("artifact_ports")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::engine("artifact declaration surface is malformed"))?;
    let new_ports = new_compiler
        .get("artifact_ports")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::engine("prospective artifact declaration surface is malformed"))?;
    if old_ports.keys().ne(new_ports.keys()) {
        return Err(Error::engine(format!(
            "advance_artifact_port_pin: the port set would change for {artifact_id}; that is a declaration change and must use update_record"
        )));
    }
    if old_descriptor.get("capability_requests") != new_compiler.get("capability_requests")
        || old_descriptor.get("module_inputs") != new_compiler.get("module_inputs")
        || old_descriptor.get("imports") != new_compiler.get("imports")
    {
        return Err(Error::engine(format!(
            "advance_artifact_port_pin: capability requests, module inputs or imports would change for {artifact_id}; that is a declaration change and must use update_record"
        )));
    }
    let old_port = old_ports.get(port_name).ok_or_else(|| {
        Error::engine(format!(
            "advance_artifact_port_pin: artifact {artifact_id} does not declare port '{port_name}'"
        ))
    })?;
    let new_port = new_ports.get(port_name).ok_or_else(|| {
        Error::engine(format!(
            "advance_artifact_port_pin: artifact {artifact_id} would no longer declare port '{port_name}'"
        ))
    })?;
    if old_port.get("schema_sha256") != new_port.get("schema_sha256") {
        return Err(Error::engine(format!(
            "advance_artifact_port_pin: port '{port_name}' would change schema_sha256; that is a real declaration change and must use update_record"
        )));
    }
    let mut allowed = old_port.clone();
    let relation = allowed
        .get_mut("relations")
        .and_then(Value::as_object_mut)
        .and_then(|relations| relations.get_mut(relation_name))
        .ok_or_else(|| {
            Error::engine(format!(
                "advance_artifact_port_pin: port '{port_name}' does not pin relation '{relation_name}'"
            ))
        })?;
    relation["semantic_version"] = json!(target_version);
    if canonical_declaration(&allowed) != canonical_declaration(new_port) {
        return Err(Error::engine(format!(
            "advance_artifact_port_pin: port '{port_name}' would change beyond the '{relation_name}' version pin; that is a declaration change and must use update_record"
        )));
    }
    Ok(())
}

/// Carry every other live binding of this artifact to the new exact source.
///
/// Writing a new body mints a new source event, and render selects a port's
/// binding by exact `artifact_source_attestation_event_id` +
/// `artifact_source_event_id` + `artifact_source_sha256`. A binding left on the
/// old source therefore disappears from render (`named_input_missing`), even
/// though its declaration did not change. This mirrors the per-port carry the
/// `update_record` lifecycle performs for unchanged ports: each carried port
/// gets an `artifact.input_carried` event whose new binding names the new
/// source and whose predecessor names the exact old one.
///
/// Only bindings tied to the old attestation are carried, which is exactly the
/// set render was selecting from before this write.
#[allow(clippy::too_many_arguments)]
async fn carry_other_bindings_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    target_port: &str,
    old_attestation_event_id: &str,
    old_source_event_id: &str,
    old_source_sha256: &str,
    old_surface: &str,
    new_attestation_event_id: &str,
    new_source_event_id: &str,
    new_source_sha256: &str,
    new_descriptor: &Value,
    new_surface: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<u64> {
    let rows = sqlx::query(
        "SELECT port_name,collection_id,event_seq FROM artifact_inputs
          WHERE artifact_id=? AND artifact_source_attestation_event_id=? AND port_name<>?
          ORDER BY port_name",
    )
    .bind(artifact_id)
    .bind(old_attestation_event_id)
    .bind(target_port)
    .fetch_all(&mut **tx)
    .await?;
    let mut carried = 0u64;
    for row in rows {
        let port: String = row.try_get("port_name")?;
        let collection_id: String = row.try_get("collection_id")?;
        let predecessor_binding_event_seq: i64 = row.try_get("event_seq")?;
        let binding = carried_input_payload(
            artifact_id,
            &port,
            &collection_id,
            new_attestation_event_id,
            new_source_event_id,
            new_source_sha256,
            new_descriptor,
        )?;
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: artifact_id.to_owned(),
                event_type: "artifact.input_carried".into(),
                payload: serde_json::to_value(ArtifactInputCarriedPayload {
                    binding,
                    predecessor_binding_event_seq,
                    predecessor_source_attestation_event_id: old_attestation_event_id.to_owned(),
                    predecessor_source_event_id: old_source_event_id.to_owned(),
                    predecessor_source_sha256: old_source_sha256.to_owned(),
                    old_declaration_surface_sha256: old_surface.to_owned(),
                    new_declaration_surface_sha256: new_surface.to_owned(),
                })?,
                actor: Some(caller.actor().into()),
            },
            act_alloc,
        )
        .await?;
        carried += 1;
    }
    Ok(carried)
}

/// Re-issue every existing capability grant against the new exact source as a
/// fresh `artifact.module_grant_set` event. Nothing is transferred: each event
/// carries a newly built attestation naming the new source event/digest.
async fn reissue_grants_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    caller: &Caller,
    artifact_id: &str,
    source_event_id: &str,
    source_sha256: &str,
    act_alloc: &mut crate::act::ActAllocation,
) -> Result<u64> {
    let rows = sqlx::query(
        "SELECT subject_kind,subject_record_id,subject_event_id,source_sha256,capability,
                scope,scope_sha256
           FROM artifact_module_grants WHERE artifact_id=?
          ORDER BY capability,subject_kind,subject_record_id,subject_event_id,source_sha256,scope_sha256",
    )
    .bind(artifact_id)
    .fetch_all(&mut **tx)
    .await?;
    if rows.is_empty() {
        return Ok(0);
    }
    let _permit = mdx::try_admit().map_err(|failure| mdx_v2_engine_error(artifact_id, failure))?;
    let mut count = 0u64;
    for row in rows {
        let mut payload = ArtifactModuleGrantPayload {
            artifact_id: artifact_id.to_owned(),
            subject_kind: row.try_get("subject_kind")?,
            subject_record_id: row.try_get("subject_record_id")?,
            subject_event_id: row.try_get("subject_event_id")?,
            source_sha256: row.try_get("source_sha256")?,
            capability: row.try_get("capability")?,
            scope: serde_json::from_str(&row.try_get::<String, _>("scope")?)?,
            scope_sha256: row.try_get("scope_sha256")?,
            attestation: None,
            attestation_sha256: None,
        };
        if payload.subject_kind == "artifact_source" {
            payload.subject_event_id = source_event_id.to_owned();
            payload.source_sha256 = source_sha256.to_owned();
        }
        let (attestation, attestation_sha256) =
            build_grant_attestation_in(tx, caller, &payload).await?;
        payload.attestation = Some(attestation);
        payload.attestation_sha256 = Some(attestation_sha256);
        verify_mdx_grant_for_projection(tx, &payload, i64::MAX).await?;
        append_in(
            db,
            tx,
            AppendSpec {
                record_id: artifact_id.to_owned(),
                event_type: "artifact.module_grant_set".into(),
                payload: serde_json::to_value(payload)?,
                actor: Some(caller.actor().into()),
            },
            act_alloc,
        )
        .await?;
        count += 1;
    }
    Ok(count)
}

pub(super) async fn advance_artifact_port_pin(
    db: Db,
    caller: Caller,
    arguments: Value,
) -> Result<Value> {
    const TOOL: &str = "advance_artifact_port_pin";
    let args: AdvanceArtifactPortPinArgs = parse_args(TOOL, arguments)?;
    if args.reason.trim().is_empty() {
        return Err(Error::engine(format!("{TOOL}: reason must not be empty")));
    }
    if args.port_name == "default" || !valid_port_name(&args.port_name) {
        return Err(Error::engine(format!(
            "{TOOL}: invalid or reserved port name"
        )));
    }
    require_record(&db, &caller, TOOL, &args.artifact_id, Capability::Edit).await?;

    // The prospective body and its compiler attestation are computed before
    // the write transaction opens; every refusal below leaves the database
    // untouched.
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='runtime'")
            .bind(&args.artifact_id)
            .fetch_optional(db.write_pool())
            .await?
            .flatten();
    let runtime = runtime.ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: artifact must be a live native.mdx.v2 or native.html.v1 artifact"
        ))
    })?;
    if !matches!(runtime.as_str(), mdx_v2::RUNTIME_ID | HTML_RUNTIME) {
        return Err(Error::engine(format!(
            "{TOOL}: artifact must be a live native.mdx.v2 or native.html.v1 artifact"
        )));
    }

    let mut tx = crate::db::begin_write(db.write_pool()).await?;
    let mut act_alloc = crate::act::ActAllocation::new();
    require_record_in(&mut tx, &caller, TOOL, &args.artifact_id, Capability::Edit).await?;

    let binding = sqlx::query(
        "SELECT collection_id,event_seq,artifact_source_attestation_event_id,
                artifact_source_event_id,artifact_source_sha256
           FROM artifact_inputs WHERE artifact_id=? AND port_name=?",
    )
    .bind(&args.artifact_id)
    .bind(&args.port_name)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: port '{}' is not bound to a governed Collection",
            args.port_name
        ))
    })?;
    let collection_id: String = binding.try_get("collection_id")?;
    let binding_source_event_id: String = binding.try_get("artifact_source_event_id")?;
    let binding_attestation_event_id: String =
        binding.try_get("artifact_source_attestation_event_id")?;
    let binding_source_sha256: String = binding.try_get("artifact_source_sha256")?;
    // Editing the saved query's version pin is itself an edit of that record.
    require_record_in(&mut tx, &caller, TOOL, &collection_id, Capability::Edit).await?;
    let collection_kind = collection_kind_in(&mut tx, &collection_id)
        .await?
        .filter(|kind| kind == "query")
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: bound Collection is not a governed query Collection"
            ))
        })?;
    let _ = collection_kind;

    let (source_event_id, source) = latest_body_source_in(&mut tx, &args.artifact_id).await?;
    let source_sha256 = mdx::sha256_hex(source.as_bytes());
    if binding_source_event_id != source_event_id
        || binding_source_sha256 != source_sha256
        || binding_attestation_event_id.is_empty()
    {
        return Err(Error::engine(format!(
            "{TOOL}: port '{}' is not bound to the exact current artifact source; rebind it with manage_artifact_inputs first",
            args.port_name
        )));
    }
    if let Some(expected) = args.if_body_digest.as_deref() {
        if expected != source_sha256 {
            return Err(Error::engine(format!(
                "{TOOL}: artifact {} changed since it was read; re-read and retry",
                args.artifact_id
            )));
        }
    }
    let old_descriptor: Value = sqlx::query_scalar(
        "SELECT descriptor FROM artifact_source_attestations
          WHERE artifact_id=? AND source_event_id=?",
    )
    .bind(&args.artifact_id)
    .bind(&source_event_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: artifact {} has no source attestation",
            args.artifact_id
        ))
    })
    .and_then(|raw: String| {
        serde_json::from_str(&raw)
            .map_err(|_| Error::engine("artifact source attestation is malformed"))
    })?;

    let port_declaration = old_descriptor
        .get("artifact_ports")
        .and_then(|ports| ports.get(&args.port_name))
        .cloned()
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: artifact does not declare port '{}'",
                args.port_name
            ))
        })?;
    let declaration: mdx_v2::InputDecl = serde_json::from_value(port_declaration)
        .map_err(|_| Error::engine(format!("{TOOL}: attested port declaration is invalid")))?;

    let relation_name = match args.relation_name.clone() {
        Some(name) => name,
        None if declaration.relations.len() == 1 => declaration
            .relations
            .keys()
            .next()
            .cloned()
            .expect("one relation"),
        None => {
            return Err(Error::engine(format!(
                "{TOOL}: port '{}' pins {} relations; name the one to advance with relation_name",
                args.port_name,
                declaration.relations.len()
            )))
        }
    };
    let pinned = declaration.relations.get(&relation_name).ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: port '{}' does not pin relation '{relation_name}'",
            args.port_name
        ))
    })?;
    let identity = pinned.identity.clone();
    let old_version = pinned.semantic_version;
    let contract = catalog_relation(&identity).ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: relation '{relation_name}' identity '{identity}' is not a governed SQL catalog relation"
        ))
    })?;
    let current_version = contract.semantic_version;
    if let Some(target) = args.target_version {
        if target != current_version {
            return Err(Error::engine(format!(
                "{TOOL}: target_version {target} is not the current catalog version {current_version} for '{identity}'; advance to current only"
            )));
        }
    }
    let target_version = args.target_version.unwrap_or(current_version);
    if old_version > current_version {
        return Err(Error::engine(format!(
            "{TOOL}: port pin '{relation_name}'@{old_version} is ahead of catalog version {current_version}; refusing to downgrade"
        )));
    }

    // The saved query pin.
    let raw: Option<String> =
        sqlx::query_scalar("SELECT value FROM facet_values WHERE record_id=? AND key='query'")
            .bind(&collection_id)
            .fetch_optional(&mut *tx)
            .await?
            .flatten();
    let raw =
        raw.ok_or_else(|| Error::engine(format!("{TOOL}: bound Collection has no saved query")))?;
    let mut definition: crate::mcp::tools::querying::SavedSqlDefinition =
        serde_json::from_str(&raw).map_err(|_| {
            Error::engine(format!(
                "{TOOL}: bound Collection saved query is not a governed SQL definition"
            ))
        })?;
    let query_pin = definition.relations.get(&relation_name).ok_or_else(|| {
        Error::engine(format!(
            "{TOOL}: saved query does not pin relation '{relation_name}'; this is not a pin-only advance"
        ))
    })?;
    if query_pin.identity != identity {
        return Err(Error::engine(format!(
            "{TOOL}: saved query relation '{relation_name}' identity '{}' does not match the port's '{}'",
            query_pin.identity, identity
        )));
    }
    let query_version = query_pin.semantic_version;
    if query_version > current_version {
        return Err(Error::engine(format!(
            "{TOOL}: saved query pin '{relation_name}'@{query_version} is ahead of catalog version {current_version}; refusing to downgrade"
        )));
    }
    let query_needs_advance = query_version != target_version;
    if query_needs_advance {
        definition
            .relations
            .get_mut(&relation_name)
            .expect("relation checked above")
            .semantic_version = target_version;
    }

    // Validate the prospective query and port declarations together. This is
    // the same exact match the runtime port resolution applies, so a successful
    // return means the port resolves again.
    let prospective_declaration = {
        let mut declaration = declaration.clone();
        declaration
            .relations
            .get_mut(&relation_name)
            .expect("relation checked above")
            .semantic_version = target_version;
        declaration
    };
    match crate::mcp::tools::querying::inspect_saved_query(Some(&serde_json::to_string(&definition)?))
    {
        crate::mcp::tools::querying::SavedQueryInspection::GovernedSql { definition } => {
            let prospective_kind = QueryRelationKind::GovernedSql {
                schema_sha256: definition.output.schema_sha256.clone(),
                relations: definition
                    .relations
                    .into_iter()
                    .map(|(name, dependency)| {
                        (
                            name,
                            mdx_v2::SemanticRelationDependency {
                                identity: dependency.identity,
                                semantic_version: dependency.semantic_version,
                            },
                        )
                    })
                    .collect(),
            };
            if !query_relation_matches_port(&prospective_kind, &prospective_declaration) {
                return Err(Error::engine(format!(
                    "{TOOL}: advancing '{relation_name}' would still leave port '{}' and the saved query incompatible; this is not a pin-only advance",
                    args.port_name
                )));
            }
        }
        crate::mcp::tools::querying::SavedQueryInspection::Invalid { diagnostic }
        | crate::mcp::tools::querying::SavedQueryInspection::UnsupportedVersion {
            diagnostic, ..
        } => {
            return Err(Error::engine(format!(
                "{TOOL}: the saved query would still be invalid after advancing '{relation_name}' to {target_version}: {diagnostic}"
            )))
        }
        crate::mcp::tools::querying::SavedQueryInspection::Valid { .. } => {
            return Err(Error::engine(format!(
                "{TOOL}: bound Collection is not governed SQL"
            )))
        }
    }

    let port_needs_advance = old_version != target_version;
    let mut new_body: Option<String> = None;
    let mut new_compiler: Option<Value> = None;
    if port_needs_advance {
        let candidate = if runtime == HTML_RUNTIME {
            repinned_html_source(
                &args.artifact_id,
                &source,
                &args.port_name,
                &relation_name,
                target_version,
            )?
        } else {
            repinned_artifact_source(
                &args.artifact_id,
                &source,
                &args.port_name,
                &relation_name,
                target_version,
            )?
        };
        let compiler = validate_prospective_artifact(
            &args.artifact_id,
            "Document",
            Some("artifact"),
            Some(&candidate),
            Some(&runtime),
        )
        .await?
        .ok_or_else(|| {
            Error::engine(format!(
                "{TOOL}: prospective artifact source is not a supported named-input artifact"
            ))
        })?;
        let (old_interactions, new_interactions) = if runtime == HTML_RUNTIME {
            (
                old_descriptor
                    .get("interactions")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
                compiler
                    .get("interactions")
                    .cloned()
                    .unwrap_or_else(|| json!([])),
            )
        } else {
            (
                artifact_interactions(&args.artifact_id, &source)?,
                artifact_interactions(&args.artifact_id, &candidate)?,
            )
        };
        assert_pin_only_change(
            &args.artifact_id,
            &args.port_name,
            &relation_name,
            target_version,
            &old_descriptor,
            &compiler,
            &old_interactions,
            &new_interactions,
        )?;
        new_body = Some(candidate);
        new_compiler = Some(compiler);
    }

    if !query_needs_advance && !port_needs_advance {
        tx.rollback().await?;
        return Ok(json!({
            "status": "unchanged",
            "artifact_id": args.artifact_id,
            "port_name": args.port_name,
            "relation_name": relation_name,
            "semantic_version": target_version,
        }));
    }

    let previous_seq = previous_record_seq_in(&mut tx, &args.artifact_id).await?;

    let query_updated = if query_needs_advance {
        append_in(
            &db,
            &mut tx,
            facet_set_spec(
                &collection_id,
                &FacetWrite {
                    key: "query".into(),
                    value: Value::String(serde_json::to_string(&definition)?),
                    vocab_ref: None,
                },
                caller.actor(),
            ),
            &mut act_alloc,
        )
        .await?;
        true
    } else {
        false
    };

    let mut source_advanced = false;
    let mut grants_reissued = 0u64;
    let mut bindings_carried = 0u64;
    if port_needs_advance {
        let body = new_body.expect("prospective body computed above");
        let compiler = new_compiler.expect("prospective compiler computed above");
        let old_surface = declaration_surface_sha256(&old_descriptor)?;
        let record_event = append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: args.artifact_id.clone(),
                event_type: "record.updated".into(),
                payload: json!({ "body": body }),
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
        let new_source_event_id = record_event.id.clone();
        let attestation_event_id = Uuid::new_v4().to_string();
        let payload = artifact_source_attestation_payload(
            &args.artifact_id,
            &attestation_event_id,
            &new_source_event_id,
            &body,
            compiler,
        )?;
        let new_descriptor = payload.artifact_source.clone();
        let new_source_sha256 = new_descriptor["source_sha256"]
            .as_str()
            .expect("artifact source payload has a verified digest")
            .to_owned();
        let new_surface = declaration_surface_sha256(&new_descriptor)?;
        append_with_event_id_in(
            &db,
            &mut tx,
            attestation_event_id.clone(),
            AppendSpec {
                record_id: args.artifact_id.clone(),
                event_type: "artifact.source_attested".into(),
                payload: serde_json::to_value(payload)?,
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
        // Every other live binding must move to the new source or render stops
        // selecting it. Do this before the target rebind so the two operations
        // read from the same pre-write `artifact_inputs` state.
        bindings_carried = carry_other_bindings_in(
            &db,
            &mut tx,
            &caller,
            &args.artifact_id,
            &args.port_name,
            &binding_attestation_event_id,
            &source_event_id,
            &source_sha256,
            &old_surface,
            &attestation_event_id,
            &new_source_event_id,
            &new_source_sha256,
            &new_descriptor,
            &new_surface,
            &mut act_alloc,
        )
        .await?;
        let rebind = carried_input_payload(
            &args.artifact_id,
            &args.port_name,
            &collection_id,
            &attestation_event_id,
            &new_source_event_id,
            &new_source_sha256,
            &new_descriptor,
        )?;
        append_in(
            &db,
            &mut tx,
            AppendSpec {
                record_id: args.artifact_id.clone(),
                event_type: "artifact.input_bound".into(),
                payload: serde_json::to_value(rebind)?,
                actor: Some(caller.actor().into()),
            },
            &mut act_alloc,
        )
        .await?;
        grants_reissued = reissue_grants_in(
            &db,
            &mut tx,
            &caller,
            &args.artifact_id,
            &new_source_event_id,
            &new_source_sha256,
            &mut act_alloc,
        )
        .await?;
        source_advanced = true;
    }

    db.commit_content(tx).await?;
    Ok(json!({
        "status": if source_advanced { "advanced" } else { "query_advanced" },
        "artifact_id": args.artifact_id,
        "collection_id": collection_id,
        "port_name": args.port_name,
        "relation_name": relation_name,
        "semantic_version": target_version,
        "query_pin_advanced": query_updated,
        "port_pin_advanced": source_advanced,
        "bindings_carried": bindings_carried,
        "grants_reissued": grants_reissued,
        "previous_seq": previous_seq,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn source_with_versions(presence: u32, claims: u32) -> String {
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{
    presence: {{
      envelope: "native.relation-envelope.v1",
      required: true,
      expose_to_root: true,
      schema_sha256: "{SCHEMA}",
      relations: {{ agent_activity: {{ identity: "native.semantic.agent_activity", semantic_version: {presence} }} }}
    }},
    claims: {{
      envelope: "native.relation-envelope.v1",
      required: true,
      expose_to_root: true,
      schema_sha256: "{SCHEMA}",
      relations: {{ agent_activity_claims: {{ identity: "native.semantic.agent_activity_claims", semantic_version: {claims} }} }}
    }}
  }},
  module_inputs: {{}},
  capability_requests: [
    {{ capability: "input.read", scope: {{ port: "presence" }} }},
    {{ capability: "input.read", scope: {{ port: "claims" }} }}
  ]
}}

<p>ok</p>
"#
        )
    }

    fn port(version: u32, schema: &str) -> Value {
        json!({
            "envelope": "native.relation-envelope.v1",
            "required": true,
            "expose_to_root": true,
            "schema_sha256": schema,
            "relations": { "agent_activity": { "identity": "native.semantic.agent_activity", "semantic_version": version } }
        })
    }

    fn descriptor(value: Value) -> Value {
        json!({
            "artifact_ports": { "presence": value },
            "capability_requests": [{ "capability": "input.read", "scope": { "port": "presence" } }],
            "module_inputs": {},
            "imports": [],
        })
    }

    #[test]
    fn repinned_source_changes_only_the_named_port_relation() {
        let original = source_with_versions(1, 1);
        let repinned =
            repinned_artifact_source("artifact", &original, "presence", "agent_activity", 2)
                .expect("repin succeeds");
        assert_ne!(repinned, original);
        assert!(repinned.ends_with("<p>ok</p>\n"));
        let parsed = mdx_v2::parse_artifact(&repinned).expect("repinned source parses");
        let manifest = match parsed.manifest {
            mdx_v2::Manifest::Artifact(manifest) => manifest,
            _ => panic!("artifact manifest"),
        };
        assert_eq!(
            manifest.inputs["presence"].relations["agent_activity"].semantic_version,
            2
        );
        assert_eq!(
            manifest.inputs["claims"].relations["agent_activity_claims"].semantic_version,
            1
        );
        assert_eq!(
            manifest.inputs["presence"].schema_sha256.as_deref(),
            Some(SCHEMA)
        );
        assert_eq!(
            manifest.inputs["claims"].schema_sha256.as_deref(),
            Some(SCHEMA)
        );
        // The authored body after the declaration is untouched.
        assert!(original.contains("semantic_version: 1"));
    }

    /// The operation's safety argument is that it changes exactly one number.
    /// The body is rebuilt by replacing the `nativeArtifact` export
    /// declaration and copying every other byte verbatim, so the author's MDX
    /// and JSX — including irregular whitespace and comments — must survive
    /// byte-for-byte. The expected full source is written out as a literal,
    /// independently of the parser, rather than derived from the same export
    /// range the implementation uses.
    #[test]
    fn repinned_source_preserves_every_byte_outside_the_manifest_declaration() {
        // The authored MDX/JSX, with irregular spacing and a JSX comment.
        let authored = "<Stack gap={3}>\n  <p>keep   this     spacing</p>\n  {/* author comment */}\n\n  <Metric label=\"Activity\" value={native.inputs.presence.relation.rows.length} />\n</Stack>\n   \n";
        let source = format!(
            "export const nativeArtifact = {{\n  schema: \"native.mdx.artifact.v2\",\n  inputs: {{\n    presence: {{\n      envelope: \"native.relation-envelope.v1\", required: true, expose_to_root: true,\n      schema_sha256: \"{SCHEMA}\",\n      relations: {{ agent_activity: {{ identity: \"native.semantic.agent_activity\", semantic_version: 1 }} }}\n    }}\n  }},\n  module_inputs: {{}},\n  capability_requests: [ {{ capability: \"input.read\", scope: {{ port: \"presence\" }} }} ]\n}}\n\n{authored}"
        );
        // The exact bytes serde produces for the manifest with the pin moved to
        // 2. Field order follows `ArtifactManifest`'s declaration; BTreeMap
        // keys are sorted; empty `interactions`, `projection` and omitted
        // defaults are absent.
        let expected_manifest = format!(
            "{{\"schema\":\"native.mdx.artifact.v2\",\"inputs\":{{\"presence\":{{\"envelope\":\"native.relation-envelope.v1\",\"required\":true,\"expose_to_root\":true,\"schema_sha256\":\"{SCHEMA}\",\"relations\":{{\"agent_activity\":{{\"identity\":\"native.semantic.agent_activity\",\"semantic_version\":2}}}}}}}},\"module_inputs\":{{}},\"capability_requests\":[{{\"capability\":\"input.read\",\"scope\":{{\"port\":\"presence\"}}}}]}}"
        );
        let expected = format!("export const nativeArtifact = {expected_manifest};\n\n{authored}");

        let repinned =
            repinned_artifact_source("artifact", &source, "presence", "agent_activity", 2)
                .expect("repin succeeds");
        assert_eq!(
            repinned, expected,
            "only the manifest declaration may change; every other byte must be identical"
        );
        // And the declaration that replaced it is the expected one.
        let parsed_repinned = mdx_v2::parse_artifact(&repinned).expect("repinned source parses");
        match parsed_repinned.manifest {
            mdx_v2::Manifest::Artifact(manifest) => assert_eq!(
                manifest.inputs["presence"].relations["agent_activity"].semantic_version,
                2
            ),
            _ => panic!("artifact manifest"),
        }
    }

    #[test]
    fn repinned_html_source_changes_only_the_inert_script_manifest() {
        let manifest = json!({
            "schema": crate::artifact_html::MANIFEST_SCHEMA,
            "inputs": {
                "presence": {
                    "envelope": "native.relation-envelope.v1",
                    "required": true,
                    "expose_to_root": true,
                    "schema_sha256": SCHEMA,
                    "relations": {
                        "agent_activity": {
                            "identity": "native.semantic.agent_activity",
                            "semantic_version": 1
                        }
                    }
                }
            },
            "capability_requests": [
                {"capability": "input.read", "scope": {"port": "presence"}}
            ]
        });
        let prefix = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Pin</title><script type=\"application/json\" id=\"native-artifact-manifest\">";
        let suffix = "</script></head><body><main><h1>Keep   these bytes</h1></main><script>const untouched = 1;</script></body></html>";
        let source = format!(
            "{prefix}{}{suffix}",
            serde_json::to_string_pretty(&manifest).unwrap()
        );
        let repinned = repinned_html_source("artifact", &source, "presence", "agent_activity", 2)
            .expect("HTML repin succeeds");
        assert!(repinned.starts_with(prefix));
        assert!(repinned.ends_with(suffix));
        let parsed = crate::artifact_html::validate(&repinned).expect("repinned HTML validates");
        assert_eq!(
            parsed.artifact_ports["presence"]["relations"]["agent_activity"]["semantic_version"],
            2
        );
    }

    #[test]
    fn repinned_html_source_refuses_an_ambiguous_manifest_copy() {
        let declaration = serde_json::to_string(&json!({
            "schema": crate::artifact_html::MANIFEST_SCHEMA,
            "inputs": {},
            "capability_requests": []
        }))
        .unwrap();
        let source = format!(
            "<script type=\"application/json\">{declaration}</script><script type=\"application/json\">{declaration}</script>"
        );
        let error = repinned_html_source("artifact", &source, "p", "r", 2)
            .expect_err("ambiguous source must fail closed");
        assert!(error.to_string().contains("unambiguous"), "{error}");
    }

    #[test]
    fn pin_only_change_accepts_a_version_bump() {
        let old = descriptor(port(1, SCHEMA));
        let new = descriptor(port(2, SCHEMA));
        assert_pin_only_change(
            "artifact",
            "presence",
            "agent_activity",
            2,
            &old,
            &new,
            &json!([]),
            &json!([]),
        )
        .expect("version-only change is admitted");
    }

    #[test]
    fn pin_only_change_refuses_a_schema_change() {
        let old = descriptor(port(1, SCHEMA));
        let new = descriptor(port(2, &"b".repeat(64)));
        let error = assert_pin_only_change(
            "artifact",
            "presence",
            "agent_activity",
            2,
            &old,
            &new,
            &json!([]),
            &json!([]),
        )
        .expect_err("schema change is refused");
        assert!(error.to_string().contains("schema_sha256"), "{error}");
    }

    #[test]
    fn pin_only_change_refuses_a_new_port() {
        let old = descriptor(port(1, SCHEMA));
        let mut new = descriptor(port(2, SCHEMA));
        new["artifact_ports"]["extra"] = port(1, SCHEMA);
        let error = assert_pin_only_change(
            "artifact",
            "presence",
            "agent_activity",
            2,
            &old,
            &new,
            &json!([]),
            &json!([]),
        )
        .expect_err("port set change is refused");
        assert!(error.to_string().contains("port set"), "{error}");
    }

    #[test]
    fn pin_only_change_refuses_a_capability_change() {
        let old = descriptor(port(1, SCHEMA));
        let mut new = descriptor(port(2, SCHEMA));
        new["capability_requests"] = json!([]);
        let error = assert_pin_only_change(
            "artifact",
            "presence",
            "agent_activity",
            2,
            &old,
            &new,
            &json!([]),
            &json!([]),
        )
        .expect_err("capability change is refused");
        assert!(error.to_string().contains("capability requests"), "{error}");
    }

    #[test]
    fn pin_only_change_refuses_an_identity_change() {
        let old = descriptor(port(1, SCHEMA));
        let mut new = descriptor(port(2, SCHEMA));
        new["artifact_ports"]["presence"]["relations"]["agent_activity"]["identity"] =
            json!("native.semantic.other");
        let error = assert_pin_only_change(
            "artifact",
            "presence",
            "agent_activity",
            2,
            &old,
            &new,
            &json!([]),
            &json!([]),
        )
        .expect_err("identity change is refused");
        assert!(error.to_string().contains("beyond"), "{error}");
    }

    #[test]
    fn pin_only_change_refuses_an_interactions_change() {
        let old = descriptor(port(1, SCHEMA));
        let new = descriptor(port(2, SCHEMA));
        let error = assert_pin_only_change(
            "artifact",
            "presence",
            "agent_activity",
            2,
            &old,
            &new,
            &json!([]),
            &json!([{ "id": "sneak", "label": "x", "effect": "facet.set" }]),
        )
        .expect_err("interactions change is refused");
        assert!(error.to_string().contains("interactions"), "{error}");
    }

    #[test]
    fn catalog_lookup_resolves_the_agents_relation() {
        let relation = catalog_relation("native.semantic.agent_activity").expect("agents relation");
        assert_eq!(
            relation.semantic_version,
            crate::query::sql_contract::AGENT_ACTIVITY_RELATION_VERSION
        );
        assert!(catalog_relation("native.semantic.not-a-relation").is_none());
    }
}
