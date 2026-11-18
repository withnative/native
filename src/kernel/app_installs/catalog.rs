//! Initial publication and updates from a host's compiled first-party catalog.
//! Catalog bytes are retained evidence; replay never consults the running release.
use super::*;

pub(crate) const PUBLISHED: &str = "kernel.app_catalog_source_published.v1";

use crate::mcp::tools::catalog_assets::{validate_catalog, verify_retained_payload};
pub use crate::mcp::tools::catalog_assets::{CatalogAssets, PublishRequest};

/// Current and replay authority share the preceding projection. Workspace-owner
/// host footing is enforced at the MCP boundary; membership is historical here.
pub(crate) async fn require_owner_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: &str,
    before: i64,
) -> Result<()> {
    consent::require_member(conn, actor, before).await?;
    let record = if before == i64::MAX {
        read_record_on(conn, actor, artifact).await?
    } else {
        read_record_unchecked_on(conn, actor, artifact).await?
    }
    .ok_or_else(|| invalid("catalog source missing"))?;
    if record.owner_id.as_deref() != Some(actor) || !is_artifact_on(conn, &record).await? {
        return Err(invalid("catalog publication requires the artifact owner"));
    }
    // A workspace shelf source is never published over in place, by anyone,
    // even its owner and even while nobody else has consented yet: members
    // consent to pins, and a new version is a new shelf pin (`shelf_add`),
    // not a rewrite of the shared artifact.
    let on_shelf: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM content_events WHERE type=? AND json_extract(payload,'$.artifact_id')=? AND seq<?)",
    )
    .bind(shelf::ADDED)
    .bind(artifact)
    .bind(before)
    .fetch_one(&mut *conn)
    .await?;
    if on_shelf {
        return Err(invalid(
            "workspace app sources are updated by adding the new version to the shelf, not by publishing over the shared source",
        ));
    }
    let facets: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_facets WHERE record_id=? AND ((key='runtime' AND value='native.html.v1') OR (key='app_package' AND value='true'))")
        .bind(artifact).fetch_one(&mut *conn).await?;
    let installed: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal=? AND package=? AND status='installed' AND json_extract(row_json,'$.artifact_id')=?)")
        .bind(actor).bind(package).bind(artifact).fetch_one(&mut *conn).await?;
    let shared: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal!=? AND status!='removed' AND json_extract(row_json,'$.artifact_id')=?)")
        .bind(actor).bind(artifact).fetch_one(&mut *conn).await?;
    if shared {
        return Err(invalid("shared app updates are not supported: another principal has an active install of this artifact"));
    }
    if facets != 2 || !installed {
        return Err(invalid(
            "catalog publication requires an existing unshared package artifact",
        ));
    }
    Ok(())
}

/// Initial publication is not an update with an invented install predecessor.
/// The exact account-only source and absence of installation history are
/// checked again during replay, before the publication event is projected.
async fn require_initial_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: &str,
    before: i64,
) -> Result<()> {
    consent::require_member(conn, actor, before).await?;
    let record = if before == i64::MAX {
        read_record_on(conn, actor, artifact).await?
    } else {
        read_record_unchecked_on(conn, actor, artifact).await?
    }
    .ok_or_else(|| invalid("catalog source missing"))?;
    if record.owner_id.as_deref() != Some(actor)
        || record.archived
        || !is_artifact_on(conn, &record).await?
    {
        return Err(invalid(
            "initial catalog publication requires the active source owner",
        ));
    }
    let anchor = kernel_policy_anchor_on(conn, &record.home_id).await?;
    let private: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=?1 AND type='kernel.home_created.v1' AND json_extract(payload,'$.source_record_id')=?2 AND seq<?4) AND (SELECT count(*) FROM kernel_policy_entries WHERE root_id=?1)=1 AND EXISTS(SELECT 1 FROM kernel_policy_entries WHERE root_id=?1 AND subject_kind='account' AND subject_id=?3 AND effect='allow' AND capability='manage') AND NOT EXISTS(SELECT 1 FROM content_events WHERE record_id=?1 AND type='kernel.import_member_policy.v1' AND seq<?4)")
        .bind(&anchor).bind(artifact).bind(actor).bind(before).fetch_one(&mut *conn).await?;
    // A one-member expanded roster is not an account-only policy. Check the
    // author's policy template as well as its effective physical entries.
    let policy: Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type='kernel.home_policy_replaced.v1' AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(&anchor).bind(before).fetch_optional(&mut *conn).await?;
    if !private
        || policy.as_ref().is_some_and(|raw| {
            serde_json::from_str::<Value>(raw).map_or(true, |p| {
                p["record_policy"]["members"].is_string() || p["record_policy"]["inherit"] == true
            })
        })
    {
        return Err(invalid(
            "initial catalog source must remain explicitly account-only",
        ));
    }
    let facets: i64 = sqlx::query_scalar("SELECT count(*) FROM kernel_facets WHERE record_id=? AND ((key='runtime' AND value='native.html.v1') OR (key='app_package' AND value='true'))")
        .bind(artifact).fetch_one(&mut *conn).await?;
    let used: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE (principal=?1 AND package=?2) OR json_extract(row_json,'$.artifact_id')=?3) OR EXISTS(SELECT 1 FROM kernel_app_package_sources WHERE artifact_id=?3)")
        .bind(actor).bind(package).bind(artifact).fetch_one(&mut *conn).await?;
    if facets != 2 || used {
        return Err(invalid(
            "initial catalog publication requires a never-installed package source",
        ));
    }
    Ok(())
}

/// First catalog sources may be prepared until their first install. Existing
/// installs retain the ordinary owner/update gate, including removed chains.
pub(crate) async fn require_source_owner_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: &str,
    revision: &str,
    before: i64,
) -> Result<()> {
    let installed: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal=? AND package=?)",
    )
    .bind(actor)
    .bind(package)
    .fetch_one(&mut *conn)
    .await?;
    let initial: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=? AND seq<? AND json_extract(payload,'$.format')=2 AND json_extract(payload,'$.source_revision')=? AND json_extract(payload,'$.entry.package')=?)")
        .bind(artifact).bind(PUBLISHED).bind(before).bind(revision).bind(package).fetch_one(&mut *conn).await?;
    if !installed && initial {
        require_initial_before_on(conn, actor, artifact, package, before).await?;
        let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_record_bodies b JOIN content_events e ON e.seq=b.event_seq WHERE b.record_id=? AND e.id=?)")
            .bind(artifact).bind(revision).fetch_one(&mut *conn).await?;
        if !current {
            return Err(Error::conflict(
                "initial catalog source body revision changed",
            ));
        }
        Ok(())
    } else {
        require_owner_before_on(conn, actor, artifact, package, before).await
    }
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn publish_as(
    db: &Db,
    actor: &str,
    assets: &CatalogAssets,
    request: PublishRequest,
) -> Result<Value> {
    if request.reason.trim().is_empty() || request.reason.len() > 1024 {
        return Err(invalid("publication reason must be 1..1024 bytes"));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_activated_on(&mut tx).await?;
    let initial = request.expected_install_event_id.is_none();
    if initial {
        if request
            .idempotency_key
            .as_deref()
            .is_none_or(|key| key.trim().is_empty())
        {
            return Err(invalid(
                "initial catalog publication requires a stable idempotency key",
            ));
        }
        require_initial_before_on(
            &mut tx,
            actor,
            &request.artifact_id,
            &request.package,
            i64::MAX,
        )
        .await?;
    } else {
        require_owner_before_on(
            &mut tx,
            actor,
            &request.artifact_id,
            &request.package,
            i64::MAX,
        )
        .await?;
    }
    let intent = serde_json::to_value(&request)?;
    let key = request.idempotency_key.as_deref().unwrap_or("");
    if key.len() > 200 {
        return Err(invalid("publication idempotency key exceeds 200 bytes"));
    }
    let prior: Option<String> = sqlx::query_scalar("SELECT payload FROM content_events WHERE record_id=? AND type=? AND actor=? AND json_extract(payload,'$.operation_key')=? ORDER BY seq DESC LIMIT 1")
        .bind(&request.artifact_id).bind(PUBLISHED).bind(actor).bind(if key.is_empty() { intent.to_string() } else { key.to_owned() }).fetch_optional(&mut *tx).await?;
    if let Some(raw) = prior {
        let prior: Value = serde_json::from_str(&raw)?;
        if prior["intent"] != intent {
            return Err(Error::conflict(
                "publication idempotency key reused for different intent",
            ));
        }
        let current: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_record_bodies b JOIN content_events e ON e.seq=b.event_seq WHERE b.record_id=? AND e.id=?)")
            .bind(&request.artifact_id).bind(prior["source_revision"].as_str()).fetch_one(&mut *tx).await?;
        let generation: Option<String> = sqlx::query_scalar(
            "SELECT generation FROM kernel_app_installs WHERE principal=? AND package=?",
        )
        .bind(actor)
        .bind(&request.package)
        .fetch_optional(&mut *tx)
        .await?;
        let current = current && serde_json::to_value(generation)? == prior["install_generation"];
        if !current {
            return Err(Error::conflict("catalog publication has been superseded"));
        }
        return Ok(prior["result"].clone());
    }
    let (entry, bytes, body) = assets.select(&request.package, &request.version)?;
    let payload: Value = serde_json::from_slice(&bytes)?;
    if !declarations::source_supported(&payload["declaration"]) {
        return Err(invalid("catalog declaration unsupported on v2"));
    }
    let generation: Option<String> = sqlx::query_scalar(
        "SELECT generation FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(actor)
    .bind(&request.package)
    .fetch_optional(&mut *tx)
    .await?;
    let previous = body_evidence::projection_on(&mut tx, &request.artifact_id).await?;
    if generation != request.expected_install_event_id
        || initial && entry["body_digest"] != request.expected_body_digest
        || previous
            .body
            .as_deref()
            .map(crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest)
            .as_deref()
            != Some(request.expected_body_digest.as_str())
    {
        return Err(Error::conflict(
            "catalog source body or install generation changed",
        ));
    }
    let predecessor = previous
        .event
        .ok_or_else(|| invalid("catalog body predecessor missing"))?;
    let revision = Uuid::new_v4().to_string();
    let id = Uuid::new_v4().to_string();
    let attestation = sources::attestation(&request.artifact_id, &id, &revision, &body)?;
    let mut acts = crate::act::ActAllocation::new();
    crate::store::append_with_event_id_on(
        db,
        &mut tx,
        revision.clone(),
        AppendSpec {
            record_id: request.artifact_id.clone(),
            event_type: "kernel.body_set.v1".into(),
            actor: Some(actor.into()),
            payload: json!({"body":body}),
        },
        &mut acts,
    )
    .await?;
    let result = json!({
        "source_revision": revision, "artifact_id": request.artifact_id,
        "package": request.package, "version": request.version,
        "declaration": payload["declaration"], "body_digest": entry["body_digest"],
        "install_generation": generation
    });
    let retained = json!({
        "format": if initial {2} else {1}, "source_revision": revision,
        "body_predecessor": predecessor.id, "expected_body_digest": request.expected_body_digest,
        "install_generation": generation, "publisher": actor, "reason": request.reason,
        "catalog": assets.catalog, "entry": entry,
        "payload_text": String::from_utf8(bytes).map_err(|_| invalid("catalog payload encoding"))?,
        "intent": intent,
        "operation_key": if key.is_empty() { intent.to_string() } else { key.to_owned() },
        "result": result, "attestation": attestation
    });
    crate::store::append_with_event_id_on(
        db,
        &mut tx,
        id,
        AppendSpec {
            record_id: request.artifact_id,
            event_type: PUBLISHED.into(),
            actor: Some(actor.into()),
            payload: retained,
        },
        &mut acts,
    )
    .await?;
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

pub(crate) fn verify(
    p: &Value,
    artifact: &str,
    event: &str,
    revision: &str,
    body: &str,
) -> Result<Value> {
    validate_catalog(&p["catalog"])?;
    let entry = &p["entry"];
    let matches: Vec<_> = p["catalog"]["entries"]
        .as_array()
        .expect("validated")
        .iter()
        .filter(|e| *e == entry)
        .collect();
    let bytes = string(p, "payload_text")?.as_bytes();
    if !matches!(p["format"].as_u64(), Some(1 | 2)) || matches.len() != 1 {
        return Err(invalid("retained catalog evidence mismatch"));
    }
    verify_retained_payload(entry, bytes, body)?;
    let intent: PublishRequest = serde_json::from_value(p["intent"].clone())?;
    let expected_result = json!({"source_revision":revision,"artifact_id":artifact,"package":entry["package"],"version":entry["version"],"declaration":serde_json::from_slice::<Value>(bytes)?["declaration"],"body_digest":entry["body_digest"],"install_generation":p["install_generation"]});
    let operation_key = intent
        .idempotency_key
        .as_deref()
        .filter(|k| !k.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| p["intent"].to_string());
    if intent.artifact_id != artifact
        || intent.package != entry["package"]
        || intent.version != entry["version"]
        || intent.expected_body_digest != p["expected_body_digest"]
        || serde_json::to_value(&intent.expected_install_event_id)? != p["install_generation"]
        || (p["format"] == 2) != intent.expected_install_event_id.is_none()
        || p["format"] == 2
            && (intent
                .idempotency_key
                .as_deref()
                .is_none_or(|key| key.trim().is_empty())
                || p["expected_body_digest"] != entry["body_digest"])
        || intent.reason != p["reason"]
        || intent.reason.trim().is_empty()
        || intent.reason.len() > 1024
        || operation_key != p["operation_key"]
        || p["result"] != expected_result
    {
        return Err(invalid(
            "catalog publication intent/result witness mismatch",
        ));
    }
    sources::verify_attestation(p, artifact, event, revision, body)?;
    Ok(serde_json::from_slice::<Value>(bytes)?["declaration"].clone())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND payload IS ? AND actor IS ? AND act IS ?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(PUBLISHED).bind(&event.payload).bind(&event.actor).bind(event.act).fetch_one(&mut *conn).await?;
    if !logged || event.event_type != PUBLISHED {
        return Err(invalid(
            "catalog publication is not a retained host outcome",
        ));
    }
    let p: Value = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("publisher missing"))?;
    let package = string(&p["entry"], "package")?;
    if p["format"] == 2 {
        require_initial_before_on(conn, actor, &event.record_id, package, event.local_seq).await?;
        let previous_publication: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=? AND seq<?)",
        )
        .bind(&event.record_id)
        .bind(PUBLISHED)
        .bind(event.local_seq)
        .fetch_one(&mut *conn)
        .await?;
        if previous_publication {
            return Err(invalid("initial catalog source was already published"));
        }
    } else {
        require_owner_before_on(conn, actor, &event.record_id, package, event.local_seq).await?;
    }
    let generation: Option<String> = sqlx::query_scalar(
        "SELECT generation FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(actor)
    .bind(package)
    .fetch_optional(&mut *conn)
    .await?;
    let (id,body,body_actor,act,seq):(String,String,Option<String>,Option<i64>,i64) = sqlx::query_as("SELECT id,json_extract(payload,'$.body'),actor,act,seq FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(&event.record_id).bind(event.local_seq).fetch_one(&mut *conn).await?;
    let previous: Option<(String,String)> = sqlx::query_as("SELECT id,CASE type WHEN 'kernel.body_set.v1' THEN json_extract(payload,'$.body') WHEN 'kernel.import_state.v1' THEN json_extract(payload,'$.state.body') WHEN 'kernel.import_state_delta.v1' THEN json_extract(payload,'$.snapshot.state.body') END FROM content_events WHERE record_id=? AND seq<? AND type IN ('kernel.body_set.v1','kernel.import_state.v1','kernel.import_state_delta.v1') ORDER BY seq DESC LIMIT 1")
        .bind(&event.record_id).bind(seq).fetch_optional(&mut *conn).await?;
    let previous = previous.ok_or_else(|| invalid("catalog predecessor missing"))?;
    if p["publisher"] != actor
        || p["install_generation"] != serde_json::to_value(generation)?
        || p["source_revision"] != id
        || p["body_predecessor"] != previous.0
        || p["expected_body_digest"]
            != crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&previous.1)
        || body_actor.as_deref() != Some(actor)
        || act.is_none()
        || act != event.act
    {
        return Err(invalid(
            "catalog publication body/install/actor witness mismatch",
        ));
    }
    verify(&p, &event.record_id, &event.id, &id, &body)?;
    Ok(())
}
