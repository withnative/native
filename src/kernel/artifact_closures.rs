//! Verified, private source closures for imported artifacts. A custody
//! capsule is evidence only; rendering never executes directly from it.
use super::*;
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub(crate) const ACTIVATED: &str = "kernel.artifact_closure_activated.v1";
pub(crate) const PREFIX: &str = "kernel:artifact-closures:";
pub(crate) const DDL: &str = "CREATE TABLE kernel_artifact_closures (
 artifact_id TEXT PRIMARY KEY REFERENCES kernel_records(id),
 source_event_id TEXT NOT NULL, source_sha256 TEXT NOT NULL,
 source_body TEXT NOT NULL, attestation_event_id TEXT NOT NULL,
 descriptor TEXT NOT NULL CHECK(json_valid(descriptor)),
 bindings TEXT NOT NULL CHECK(json_valid(bindings)),
 grants TEXT NOT NULL CHECK(json_valid(grants)), event_seq INTEGER NOT NULL)";

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Activation {
    format: u32,
    source_head: Value,
    report_sha256: String,
    artifact_id: String,
    capsule_seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    frozen_legacy: Option<FrozenLegacy>,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FrozenLegacy {
    source_event_id: String,
    source_sha256: String,
    runtime: String,
    renders: Vec<String>,
}

/// Host-verified completion of one frozen artifact closure. This is not an MCP
/// input and cannot be manufactured by an app or a record owner.
#[derive(Clone)]
pub struct VerifiedArtifactClosure(Activation);

impl VerifiedArtifactClosure {
    /// # Safety
    /// The host must freeze and verify this artifact's exact source, inputs,
    /// grants and dependencies at the supplied source head. Importers must be
    /// excluded from the promoted serving generation before activation.
    pub unsafe fn from_verified_import_unchecked(
        source_head: Value,
        report_sha256: String,
        artifact_id: String,
        capsule_seq: i64,
    ) -> Self {
        Self(Activation {
            format: 1,
            source_head,
            report_sha256,
            artifact_id,
            capsule_seq,
            frozen_legacy: None,
        })
    }
}

impl VerifiedArtifactClosure {
    /// Native host attestation for legacy sources that have no v1 attestation.
    /// # Safety
    /// The supplied source revision, runtime and renders edges must be verified
    /// against the complete frozen import; serving/importer custody is exclusive.
    pub unsafe fn from_verified_legacy_import_unchecked(
        source_head: Value,
        report_sha256: String,
        artifact_id: String,
        source_event_id: String,
        source_sha256: String,
        runtime: String,
        renders: Vec<String>,
    ) -> Self {
        Self(Activation {
            format: 2,
            source_head,
            report_sha256,
            artifact_id,
            capsule_seq: 0,
            frozen_legacy: Some(FrozenLegacy {
                source_event_id,
                source_sha256,
                runtime,
                renders,
            }),
        })
    }
}

struct Captured {
    source_event_id: String,
    source_sha256: String,
    body: String,
    attestation_event_id: String,
    descriptor: Value,
    bindings: Vec<Value>,
    grants: Vec<Value>,
}

fn invalid(why: &str) -> Error {
    Error::engine(format!("native artifact activation: {why}"))
}

fn string<'a>(row: &'a Value, field: &str) -> Result<&'a str> {
    row[field]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("incomplete source evidence"))
}

fn source_event_at<'a>(state: &'a app_state::RetainedAppState, seq: &Value) -> Result<&'a Value> {
    let event_seq = seq
        .as_i64()
        .ok_or_else(|| invalid("source event sequence missing"))?;
    state
        .source_events
        .values()
        .find(|event| event["seq"] == event_seq)
        .ok_or_else(|| invalid("source projection witness missing"))
}

pub(crate) async fn ensure_schema(conn: &mut SqliteConnection) -> Result<()> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kernel_artifact_closures')")
        .fetch_one(&mut *conn).await?;
    if exists {
        return Ok(());
    }
    sqlx::query(DDL).execute(&mut *conn).await?;
    let events = crate::conformance::rebuild::read_events_of_types(conn, &[ACTIVATED]).await?;
    for event in &events {
        project(conn, event).await?;
    }
    Ok(())
}

async fn verify(conn: &mut SqliteConnection, p: &Activation, before: i64) -> Result<Captured> {
    if !matches!(p.format, 1 | 2)
        || p.artifact_id.is_empty()
        || p.capsule_seq >= before
        || p.report_sha256.len() != 64
        || !p
            .report_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(invalid("invalid verification receipt"));
    }
    let roster: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE type=? AND seq<?)",
    )
    .bind(hosted_identity::ROSTER_EVENT)
    .bind(before)
    .fetch_one(&mut *conn)
    .await?;
    if !roster {
        return Err(invalid("hosted identity activation required"));
    }
    let head: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE type='kernel.import_source_head.v1' AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(before).fetch_optional(&mut *conn).await?;
    if head
        .map(|s| serde_json::from_str::<Value>(&s))
        .transpose()?
        .as_ref()
        != Some(&p.source_head)
    {
        return Err(invalid("frozen source head changed"));
    }
    if p.format == 2 {
        return verify_legacy(conn, p, before).await;
    }
    if p.frozen_legacy.is_some() {
        return Err(invalid("unexpected native legacy attestation"));
    }
    let (origin, state) =
        app_state::evidence_at(conn, &p.artifact_id, p.capsule_seq, before).await?;
    let frontier = state
        .custody
        .as_ref()
        .ok_or_else(|| invalid("capsule frontier missing"))?;
    if state.source_deleted
        || p.source_head["origin"] != origin
        || frontier.format != 1
        || frontier.content_frontier != p.source_head["seq"].as_i64().unwrap_or(-1)
        || frontier.control_frontier != p.source_head["control_seq"].as_i64().unwrap_or(-1)
        || !frontier.missing_source_events.is_empty()
        || !frontier.missing_control_events.is_empty()
    {
        return Err(invalid("incomplete or stale source capsule"));
    }
    // A module closure needs release/grant semantics of its own. Refuse it
    // until that separate activation lane exists.
    if !state.module_releases.is_empty() || !state.module_release_imports.is_empty() {
        return Err(invalid("module closure unsupported on v2"));
    }
    let mut selected = None;
    for row in &state.artifact_source_attestations {
        let seq = row["event_seq"]
            .as_i64()
            .ok_or_else(|| invalid("attestation sequence missing"))?;
        if selected
            .as_ref()
            .is_none_or(|(highest, _): &(i64, &Value)| seq > *highest)
        {
            selected = Some((seq, row));
        }
    }
    let (_, row) = selected.ok_or_else(|| invalid("source attestation missing"))?;
    let source_event_id = string(row, "source_event_id")?.to_owned();
    let source_sha256 = string(row, "source_sha256")?.to_owned();
    let attestation_event_id = string(row, "attestation_event_id")?.to_owned();
    let source_event = state
        .source_events
        .get(&source_event_id)
        .ok_or_else(|| invalid("source event missing"))?;
    if source_event["record_id"] != p.artifact_id {
        return Err(invalid("source bearer mismatch"));
    }
    let source_payload: Value = serde_json::from_str(string(source_event, "payload")?)?;
    let body = string(&source_payload, "body")?.to_owned();
    if native_artifact_runtime::mdx::sha256_hex(body.as_bytes()) != source_sha256 {
        return Err(invalid("source digest mismatch"));
    }
    let descriptor: Value = serde_json::from_str(string(row, "descriptor")?)?;
    let attestation = state
        .source_events
        .get(&attestation_event_id)
        .ok_or_else(|| invalid("attestation event missing"))?;
    if attestation["record_id"] != p.artifact_id
        || attestation["type"] != "artifact.source_attested"
        || attestation["seq"] != row["event_seq"]
    {
        return Err(invalid("attestation witness mismatch"));
    }
    let attested: Value = serde_json::from_str(string(attestation, "payload")?)?;
    if attested["artifact_source"] != descriptor
        || attested["attestation_sha256"] != row["attestation_sha256"]
    {
        return Err(invalid("attestation descriptor mismatch"));
    }
    let runtime = descriptor["runtime"]
        .as_str()
        .unwrap_or(native_artifact_runtime::mdx_v2::RUNTIME_ID)
        .to_owned();
    let (manifest, compiler) = if runtime == crate::artifact_html::RUNTIME_ID {
        let limit = html_limit_on(conn, &p.artifact_id).await?;
        let html = crate::artifact_html::validate_cached_with_limit(&body, limit)
            .map_err(|_| invalid("HTML source validator refused artifact"))?;
        let compiler = json!({"runtime":runtime,"artifact_ports":html.artifact_ports,
            "imports":[],"module_inputs":{},"capability_requests":html.capability_requests,
            "interactions":html.interactions,"diagnostics":html.diagnostics});
        (html.interaction_manifest(), compiler)
    } else {
        let parsed = native_artifact_runtime::mdx_v2::parse_artifact(&body)
            .map_err(|_| invalid("source compiler refused artifact"))?;
        if !parsed.imports.is_empty() {
            return Err(invalid("module or runtime closure unsupported"));
        }
        let native_artifact_runtime::mdx_v2::Manifest::Artifact(manifest) = parsed.manifest else {
            return Err(invalid("source is not an MDX artifact"));
        };
        let compiler = json!({"artifact_ports":manifest.inputs,"imports":[],
            "module_inputs":manifest.module_inputs,"capability_requests":manifest.capability_requests});
        (manifest, compiler)
    };
    let mut expected = crate::mcp::tools::artifacts::artifact_source_attestation_payload(
        &p.artifact_id,
        &attestation_event_id,
        &source_event_id,
        &body,
        compiler,
    )?;
    // The v1 HTML descriptor acquired these optional fields additively. An
    // old attestation remains exact authority for its original byte shape;
    // absence must never manufacture newly declared executable effects.
    if runtime == crate::artifact_html::RUNTIME_ID {
        if descriptor.get("interactions").is_none() {
            if !manifest.interactions.is_empty() {
                return Err(invalid("unattested HTML interactions"));
            }
            expected
                .artifact_source
                .as_object_mut()
                .unwrap()
                .remove("interactions");
        }
        if descriptor.get("write_diagnostics").is_none() {
            expected
                .artifact_source
                .as_object_mut()
                .unwrap()
                .remove("write_diagnostics");
        }
        expected.attestation_sha256 =
            crate::mcp::tools::artifacts::mdx_sha256_for_projection(&expected.artifact_source);
    }
    if serde_json::to_value(&expected)? != attested {
        return Err(invalid("attestation does not describe current source"));
    }
    let mut descriptor = descriptor;
    if runtime == crate::artifact_html::RUNTIME_ID {
        descriptor["_kernel_legacy_renders"] =
            json!(legacy_renders_on(conn, &p.artifact_id).await?);
    }
    let mut bindings = Vec::new();
    let mut seen = BTreeMap::new();
    for binding in &state.artifact_inputs {
        if binding["artifact_source_attestation_event_id"] == attestation_event_id
            && binding["artifact_source_event_id"] == source_event_id
            && binding["artifact_source_sha256"] == source_sha256
        {
            let port = string(binding, "port_name")?;
            if seen.insert(port.to_owned(), ()).is_some() {
                return Err(invalid("duplicate input binding"));
            }
            string(binding, "collection_id")?;
            let witness = source_event_at(&state, &binding["event_seq"])?;
            if witness["record_id"] != p.artifact_id {
                return Err(invalid("input event bearer mismatch"));
            }
            let payload: Value = serde_json::from_str(string(witness, "payload")?)?;
            let detail = match witness["type"].as_str() {
                Some("artifact.input_bound") => &payload,
                Some("artifact.input_carried") => &payload["binding"],
                _ => return Err(invalid("input event type mismatch")),
            };
            for key in [
                "artifact_id",
                "port_name",
                "collection_id",
                "artifact_source_attestation_event_id",
                "artifact_source_event_id",
                "artifact_source_sha256",
            ] {
                if detail[key] != binding[key] {
                    return Err(invalid("input event witness mismatch"));
                }
            }
            bindings.push(binding.clone());
        }
    }
    if seen.keys().any(|port| !manifest.inputs.contains_key(port))
        || (runtime != crate::artifact_html::RUNTIME_ID
            && manifest
                .inputs
                .iter()
                .any(|(port, declaration)| declaration.required && !seen.contains_key(port)))
    {
        return Err(invalid(
            "named input bindings do not match source declaration",
        ));
    }
    let mut grants = Vec::new();
    for grant in &state.artifact_module_grants {
        if grant["artifact_source_attestation_event_id"] != attestation_event_id
            || grant["artifact_source_event_id"] != source_event_id
            || grant["artifact_source_sha256"] != source_sha256
        {
            continue;
        }
        let witness = source_event_at(&state, &grant["event_seq"])?;
        if witness["record_id"] != p.artifact_id {
            return Err(invalid("grant event bearer mismatch"));
        }
        let payload: Value = serde_json::from_str(string(witness, "payload")?)?;
        let detail = match witness["type"].as_str() {
            Some("artifact.module_grant_set") => &payload,
            Some("artifact.module_grant_carried") => &payload["grant"],
            _ => return Err(invalid("grant event type mismatch")),
        };
        for key in [
            "artifact_id",
            "subject_kind",
            "subject_record_id",
            "subject_event_id",
            "source_sha256",
            "capability",
            "scope_sha256",
        ] {
            if detail[key] != grant[key] {
                return Err(invalid("grant event witness mismatch"));
            }
        }
        for (source_key, projection_key) in [
            (
                "artifact_source_attestation_event_id",
                "artifact_source_attestation_event_id",
            ),
            ("artifact_source_event_id", "artifact_source_event_id"),
            ("artifact_source_sha256", "artifact_source_sha256"),
        ] {
            if detail["attestation"][source_key] != grant[projection_key] {
                return Err(invalid("grant attestation witness mismatch"));
            }
        }
        let scope: Value = serde_json::from_str(string(grant, "scope")?)?;
        if detail["scope"] != scope {
            return Err(invalid("grant scope witness mismatch"));
        }
        grants.push(grant.clone());
    }
    Ok(Captured {
        source_event_id,
        source_sha256,
        body,
        attestation_event_id,
        descriptor,
        bindings,
        grants,
    })
}

pub async fn activate_as(db: &Db, host: &str, proof: VerifiedArtifactClosure) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    ensure_schema(&mut tx).await?;
    activate_on(db, &mut tx, host, &proof).await?;
    db.commit_kernel_content(tx).await?;
    Ok(())
}

async fn refuse_excluded_on(conn: &mut SqliteConnection, id: &str, before: i64) -> Result<()> {
    let excluded: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type=? AND record_id=? AND seq<?)",
    )
    .bind(EXCLUDED)
    .bind(format!("{PREFIX}excluded:{id}"))
    .bind(before)
    .fetch_one(conn)
    .await?;
    if excluded {
        return Err(invalid("artifact already excluded"));
    }
    Ok(())
}

pub(crate) async fn activate_on(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    host: &str,
    proof: &VerifiedArtifactClosure,
) -> Result<()> {
    refuse_excluded_on(tx, &proof.0.artifact_id, i64::MAX).await?;
    let already = inspect_frozen_activation_on(tx, proof).await?;
    if already {
        return Ok(());
    }
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: format!("{PREFIX}{}", proof.0.artifact_id),
            event_type: ACTIVATED.into(),
            payload: serde_json::to_value(&proof.0)?,
            actor: Some(host.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    Ok(())
}

/// Read-only preflight shared with activation; no schema preparation or writes.
pub async fn inspect_frozen_activation_on(
    tx: &mut SqliteConnection,
    proof: &VerifiedArtifactClosure,
) -> Result<bool> {
    let id = &proof.0.artifact_id;
    let prior: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM main.content_events WHERE type=? AND record_id=? ORDER BY seq LIMIT 1",
    )
    .bind(ACTIVATED)
    .bind(format!("{PREFIX}{id}"))
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(prior) = prior {
        if serde_json::from_str::<Activation>(&prior)? != proof.0 {
            return Err(Error::conflict("artifact activation evidence changed"));
        }
        return Ok(true);
    }
    let captured = verify(&mut *tx, &proof.0, i64::MAX).await?;
    let current: Option<(String, i64)> =
        sqlx::query_as("SELECT body,event_seq FROM kernel_record_bodies WHERE record_id=?")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let first_roster: i64 =
        sqlx::query_scalar("SELECT min(seq) FROM main.content_events WHERE type=?")
            .bind(hosted_identity::ROSTER_EVENT)
            .fetch_one(&mut *tx)
            .await?;
    if current
        .as_ref()
        .is_none_or(|(body, seq)| body != &captured.body || *seq >= first_roster)
        || hq::tombstoned_on(&mut *tx, id).await?
    {
        return Err(invalid("current record source changed"));
    }
    let host: String =
        sqlx::query_scalar("SELECT principal_id FROM kernel_principals WHERE auth_binding=?")
            .bind(HOST_IMPORT_BINDING)
            .fetch_one(&mut *tx)
            .await?;
    let record = read_record_unchecked_on(&mut *tx, &host, id)
        .await?
        .ok_or_else(|| invalid("artifact record missing"))?;
    let primary: Option<String> =
        sqlx::query_scalar("SELECT primary_type FROM kernel_records WHERE id=?")
            .bind(id)
            .fetch_one(&mut *tx)
            .await?;
    if !is_artifact_kind_on(
        &mut *tx,
        crate::v2_standard::v1_compat::v1_type_and_kind(
            record.family.as_deref(),
            record.pin.as_ref().map(|pin| pin.version),
            primary.as_deref(),
            record.kind.as_deref(),
            &record.fields,
        ),
    )
    .await?
    {
        return Err(invalid("source is not a live Document/artifact"));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    if runtime.as_deref()
        != Some(
            captured.descriptor["runtime"]
                .as_str()
                .unwrap_or(native_artifact_runtime::mdx_v2::RUNTIME_ID),
        )
    {
        return Err(invalid("artifact runtime does not match frozen source"));
    }
    // Equal text is insufficient: v1 binds an attestation to a source event,
    // and a later edit can reintroduce the same bytes under a new event ID.
    // Require the completed W5 history to identify that current body revision.
    let latest_body_source: Option<String> = sqlx::query_scalar(
        "SELECT h.source_id FROM kernel_legacy_sql_events h
         JOIN main.content_events e ON e.seq=h.seq
         WHERE h.record_id=? AND h.source_stream='content_events'
           AND h.event_type IN ('record.created','record.updated','receipt.committed.v1')
           AND json_type(e.payload,'$.legacy.payload.body') IS NOT NULL
         ORDER BY h.seq DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?;
    if latest_body_source.as_deref() != Some(&captured.source_event_id) {
        return Err(invalid("exact current source revision is not attested"));
    }
    Ok(false)
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Activation = event_payload(event)?;
    if event.record_id != format!("{PREFIX}{}", p.artifact_id) {
        return Err(invalid("activation aggregate mismatch"));
    }
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    app_state::refuse_entity_collision(conn, &event.record_id).await?;
    refuse_excluded_on(conn, &p.artifact_id, event.local_seq).await?;
    let captured = verify(conn, &p, event.local_seq).await?;
    let inserted = sqlx::query("INSERT INTO kernel_artifact_closures (artifact_id,source_event_id,source_sha256,source_body,attestation_event_id,descriptor,bindings,grants,event_seq) VALUES (?,?,?,?,?,?,?,?,?)")
        .bind(&p.artifact_id).bind(captured.source_event_id).bind(captured.source_sha256)
        .bind(captured.body).bind(if captured.attestation_event_id == "$activation" {
            event.id.clone()
        } else { captured.attestation_event_id })
        .bind(serde_json::to_string(&captured.descriptor)?)
        .bind(serde_json::to_string(&captured.bindings)?)
        .bind(serde_json::to_string(&captured.grants)?)
        .bind(event.local_seq).execute(&mut *conn).await;
    inserted.map_err(|_| invalid("duplicate or orphaned artifact activation"))?;
    Ok(())
}

/// Artifact identity follows v1's governed kind aliases; archival is metadata,
/// while tombstones and the caller's View check remain separate requirements.
pub(crate) async fn is_artifact_kind_on(
    conn: &mut SqliteConnection,
    kind: (Option<&str>, Option<&str>),
) -> Result<bool> {
    match kind {
        (Some("Document"), Some("artifact")) => Ok(true),
        (Some("Document"), Some(raw)) => {
            let interpreter = crate::query::lifecycle::LifecycleInterpreter::from_imported_rows(
                Vec::new(),
                v1_state::rows_on(conn, "vocabularies").await?,
                v1_state::rows_on(conn, "vocabulary_values").await?,
            )?;
            Ok(interpreter.canonical_imported_kind("Document", raw) == "artifact")
        }
        _ => Ok(false),
    }
}

pub(crate) async fn html_limit_on(conn: &mut SqliteConnection, id: &str) -> Result<usize> {
    let marker: Option<String> = sqlx::query_scalar(
        "SELECT value FROM kernel_facets WHERE record_id=? AND key='app_package'",
    )
    .bind(id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(crate::artifact_html::body_limit_for_package_marker(
        marker.as_deref(),
    ))
}

pub(crate) async fn legacy_renders_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Vec<String>> {
    Ok(sqlx::query_scalar("SELECT target_id FROM kernel_links WHERE source_id=?1 AND relationship='renders'
        UNION SELECT target_id FROM kernel_generic_links WHERE source_id=?1 AND relationship='renders' AND active=1 ORDER BY target_id")
        .bind(id).fetch_all(&mut *conn).await?)
}

async fn verify_legacy(
    conn: &mut SqliteConnection,
    p: &Activation,
    before: i64,
) -> Result<Captured> {
    let frozen = p
        .frozen_legacy
        .as_ref()
        .ok_or_else(|| invalid("native frozen source evidence missing"))?;
    if p.capsule_seq != 0
        || !matches!(
            frozen.runtime.as_str(),
            "native.html.v1" | "native.board.v1"
        )
    {
        return Err(invalid("unsupported native frozen source"));
    }
    // This lane cannot replace the current v1 attestation or bypass its
    // grants/bindings. Old source revisions remain custody only: v1 ordinary
    // non-named HTML/board rendering does not require those old attestations.
    let custody: Option<String> =
        sqlx::query_scalar("SELECT payload FROM kernel_app_state WHERE record_id=?")
            .bind(&p.artifact_id)
            .fetch_optional(&mut *conn)
            .await?;
    if let Some(custody) = custody {
        let state: app_state::RetainedAppState = serde_json::from_str(&custody)?;
        if state.source_deleted
            || state
                .artifact_source_attestations
                .iter()
                .any(|row| row["source_event_id"] == frozen.source_event_id)
            || state
                .artifact_inputs
                .iter()
                .any(|row| row["artifact_source_event_id"] == frozen.source_event_id)
            || state
                .artifact_module_grants
                .iter()
                .any(|row| row["artifact_source_event_id"] == frozen.source_event_id)
        {
            return Err(invalid("legacy source requires its retained v1 closure"));
        }
    }
    let raw: Option<String> = sqlx::query_scalar("SELECT json_extract(payload,'$.legacy') FROM main.content_events
        WHERE record_id=? AND type='kernel.legacy_recorded.v1' AND seq<?
          AND json_extract(payload,'$.legacy.event_type') IN ('record.created','record.updated','receipt.committed.v1')
          AND json_type(payload,'$.legacy.payload.body') IS NOT NULL
        ORDER BY seq DESC LIMIT 1")
        .bind(&p.artifact_id).bind(before).fetch_optional(&mut *conn).await?;
    let legacy: hq::LegacyEvent =
        serde_json::from_str(&raw.ok_or_else(|| invalid("complete body history required"))?)?;
    let body = string(&legacy.payload, "body")?.to_owned();
    let metadata = legacy
        .source
        .ok_or_else(|| invalid("source provenance missing"))?;
    if metadata["origin"] != p.source_head["origin"]
        || metadata["stream"] != "content_events"
        || legacy.id != frozen.source_event_id
        || native_artifact_runtime::mdx::sha256_hex(body.as_bytes()) != frozen.source_sha256
    {
        return Err(invalid("native frozen source witness mismatch"));
    }
    let renders = legacy_renders_on(conn, &p.artifact_id).await?;
    if renders != frozen.renders || renders.len() > 1 {
        return Err(invalid("frozen renders binding changed"));
    }
    let mut descriptor = json!({"schema":"native.frozen-artifact-source.v1","runtime":frozen.runtime,
        "source_event_id":frozen.source_event_id,"source_sha256":frozen.source_sha256,
        "_kernel_legacy_renders":renders});
    if frozen.runtime == crate::artifact_html::RUNTIME_ID {
        let manifest = crate::artifact_html::validate_cached_with_limit(
            &body,
            html_limit_on(conn, &p.artifact_id).await?,
        )
        .map_err(|_| invalid("HTML source validator refused artifact"))?;
        if manifest.named_inputs_declared {
            return Err(invalid("named HTML requires a v1 source attestation"));
        }
        descriptor["profile"] = json!(manifest.profile.as_str());
    } else {
        crate::mcp::tools::artifacts::render_board_compat(&body, "standalone", None, Vec::new())
            .map_err(|_| invalid("board source validator refused artifact"))?;
    }
    Ok(Captured {
        source_event_id: frozen.source_event_id.clone(),
        source_sha256: frozen.source_sha256.clone(),
        body,
        attestation_event_id: "$activation".into(),
        descriptor,
        bindings: Vec::new(),
        grants: Vec::new(),
    })
}

/// Host-retained refusal, never an executable closure. Each diagnostic belongs
/// to the admitted native principal whose frozen v1 read produced it.
pub(crate) const EXCLUDED: &str = "kernel.artifact_excluded.v1";
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FrozenExclusion {
    pub format: u32,
    pub source_head: Value,
    pub report_sha256: String,
    pub artifact_id: String,
    pub capsule_seq: Option<i64>,
    pub outcomes: BTreeMap<String, Value>,
}

impl FrozenExclusion {
    fn aggregate(&self) -> String {
        format!("{PREFIX}excluded:{}", self.artifact_id)
    }
}

async fn verify_exclusion_on(
    conn: &mut SqliteConnection,
    p: &FrozenExclusion,
    before: i64,
) -> Result<()> {
    let head: Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE type='kernel.import_source_head.v1' AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(before).fetch_optional(&mut *conn).await?;
    if let Some(seq) = p.capsule_seq {
        let (origin, state) = app_state::evidence_at(conn, &p.artifact_id, seq, before).await?;
        let frontier = state
            .custody
            .as_ref()
            .ok_or_else(|| invalid("exclusion custody missing"))?;
        if p.source_head["origin"] != origin
            || state.source_deleted
            || frontier.format != 1
            || frontier.content_frontier != p.source_head["seq"].as_i64().unwrap_or(-1)
            || frontier.control_frontier != p.source_head["control_seq"].as_i64().unwrap_or(-1)
            || !frontier.missing_source_events.is_empty()
            || !frontier.missing_control_events.is_empty()
        {
            return Err(invalid("incomplete or stale exclusion custody"));
        }
    } else {
        // Import intentionally omits an initial empty capsule. Absence is only
        // valid when no retained custody event ever established this bearer.
        let retained: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type=? AND json_extract(payload,'$.bearer')=? AND seq<?)")
            .bind(app_state::IMPORTED_EVENT).bind(&p.artifact_id).bind(before).fetch_one(&mut *conn).await?;
        if retained {
            return Err(invalid("exclusion custody missing"));
        }
    }
    if p.format != 1
        || p.report_sha256.len() != 64
        || !p.report_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || head
            .map(|s| serde_json::from_str::<Value>(&s))
            .transpose()?
            .as_ref()
            != Some(&p.source_head)
        || hq::tombstoned_on(conn, &p.artifact_id).await?
    {
        return Err(invalid("incomplete or stale exclusion custody"));
    }
    let roster: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE type=? AND seq<?)")
            .bind(hosted_identity::ROSTER_EVENT)
            .bind(before)
            .fetch_one(&mut *conn)
            .await?;
    if !roster {
        return Err(invalid("hosted identity activation required"));
    }
    let imported: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records r WHERE r.id=? AND r.created_seq<(SELECT min(seq) FROM content_events WHERE type=?))")
        .bind(&p.artifact_id).bind(hosted_identity::ROSTER_EVENT).fetch_one(&mut *conn).await?;
    if !imported {
        return Err(invalid("exclusion source is not an imported record"));
    }
    for (actor, outcome) in &p.outcomes {
        if !hosted_identity::admitted(conn, actor).await?
            || outcome["status"] == "rendered"
            || outcome["diagnostic"]["code"].as_str().is_none()
        {
            return Err(invalid("invalid exclusion outcome"));
        }
    }
    let activated: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_artifact_closures WHERE artifact_id=?)",
    )
    .bind(&p.artifact_id)
    .fetch_one(&mut *conn)
    .await?;
    if activated {
        return Err(invalid("artifact already has an executable closure"));
    }
    Ok(())
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn inspect_exclusion_on(
    conn: &mut SqliteConnection,
    proof: &FrozenExclusion,
) -> Result<bool> {
    let prior: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM content_events WHERE type=? AND record_id=? ORDER BY seq LIMIT 1",
    )
    .bind(EXCLUDED)
    .bind(proof.aggregate())
    .fetch_optional(&mut *conn)
    .await?;
    if let Some(prior) = prior {
        if serde_json::from_str::<FrozenExclusion>(&prior)? != *proof {
            return Err(invalid("artifact exclusion evidence changed"));
        }
        return Ok(true);
    }
    verify_exclusion_on(conn, proof, i64::MAX).await?;
    Ok(false)
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn exclude_on(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    host: &str,
    proof: &FrozenExclusion,
) -> Result<()> {
    if inspect_exclusion_on(tx, proof).await? {
        return Ok(());
    }
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: proof.aggregate(),
            event_type: EXCLUDED.into(),
            payload: serde_json::to_value(proof)?,
            actor: Some(host.into()),
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    Ok(())
}

pub(crate) async fn project_exclusion(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: FrozenExclusion = event_payload(event)?;
    if event.record_id != p.aggregate() {
        return Err(invalid("exclusion aggregate mismatch"));
    }
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    app_state::refuse_entity_collision(conn, &event.record_id).await?;
    verify_exclusion_on(conn, &p, event.local_seq).await
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn unsupported_outcome(id: &str) -> Value {
    crate::mcp::tools::artifacts::diagnostic(
        "unsupported_on_v2",
        "this imported artifact is unsupported on v2",
        json!({"artifact_id":id}),
    )
}

/// Called only after fresh serving authorization. This is a frozen refusal,
/// never source authority; new members receive no other member's diagnostic.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn exclusion_outcome_on(
    conn: &mut SqliteConnection,
    actor: &str,
    id: &str,
) -> Result<Option<Value>> {
    if hq::tombstoned_on(conn, id).await? || !hosted_identity::admitted(conn, actor).await? {
        return Ok(None);
    }
    let prior: Option<(String, i64)> = sqlx::query_as(
        "SELECT payload,seq FROM content_events WHERE type=? AND record_id=? ORDER BY seq LIMIT 1",
    )
    .bind(EXCLUDED)
    .bind(format!("{PREFIX}excluded:{id}"))
    .fetch_optional(&mut *conn)
    .await?;
    let Some((prior, seq)) = prior else {
        return Ok(None);
    };
    let proof: FrozenExclusion = serde_json::from_str(&prior)?;
    let edited: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_record_bodies WHERE record_id=? AND event_seq>?) OR EXISTS(SELECT 1 FROM kernel_facets WHERE record_id=? AND key='runtime' AND event_seq>?)",
    )
    .bind(id)
    .bind(seq)
    .bind(id)
    .bind(seq)
    .fetch_one(&mut *conn)
    .await?;
    Ok(Some(if edited {
        unsupported_outcome(id)
    } else {
        proof
            .outcomes
            .get(actor)
            .cloned()
            .unwrap_or_else(|| unsupported_outcome(id))
    }))
}
