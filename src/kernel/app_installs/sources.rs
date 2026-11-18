//! Host-attested revisions of an owner's personal HTML app.
//! Publication grants source authority only; execution switches through a guarded
//! install with verified consent carry or fresh adoption.
use super::*;

pub(crate) const PUBLISHED: &str = "kernel.app_source_published.v1";

async fn never_installed_on(conn: &mut SqliteConnection, artifact: &str) -> Result<bool> {
    // Retained source pins survive removal and replacement of a package's
    // current row, so that replacement cannot make an old source virgin again.
    Ok(sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM kernel_app_installs WHERE json_extract(row_json,'$.artifact_id')=?) AND NOT EXISTS(SELECT 1 FROM kernel_app_package_sources WHERE artifact_id=?)")
        .bind(artifact).bind(artifact).fetch_one(conn).await?)
}

/// First publication may retain a guarded body even when its bytes did not
/// change. Later no-op edits keep ordinary no-op semantics.
pub(crate) async fn needs_initial_publication_on(
    conn: &mut SqliteConnection,
    artifact: &str,
) -> Result<bool> {
    if !never_installed_on(conn, artifact).await? {
        return Ok(false);
    }
    Ok(sqlx::query_scalar(
        "SELECT NOT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=?)",
    )
    .bind(artifact)
    .bind(PUBLISHED)
    .fetch_one(conn)
    .await?)
}

pub(crate) async fn require_owner_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: Option<&str>,
) -> Result<()> {
    require_owner_with_initial_before_on(conn, actor, artifact, package, i64::MAX, true).await
}

/// Retained events recheck the preceding projection and historical roster.
/// They cannot gain or lose source authority from a later offboarding event.
pub(super) async fn require_owner_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: Option<&str>,
    before: i64,
) -> Result<()> {
    require_owner_with_initial_before_on(conn, actor, artifact, package, before, false).await
}

async fn require_owner_with_initial_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: Option<&str>,
    before: i64,
    allow_initial: bool,
) -> Result<()> {
    consent::require_member(conn, actor, before).await?;
    let record = if before == i64::MAX {
        read_record_on(conn, actor, artifact).await?
    } else {
        read_record_unchecked_on(conn, actor, artifact).await?
    }
    .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    if record.owner_id.as_deref() != Some(actor) || !is_artifact_on(conn, &record).await? {
        return Err(invalid(
            "only the source artifact owner can update an existing personal app",
        ));
    }
    let facets: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT key,value FROM kernel_facets WHERE record_id=? AND key IN ('runtime','app_package')")
        .bind(artifact).fetch_all(&mut *conn).await?;
    if !facets
        .iter()
        .any(|(k, v)| k == "runtime" && v.as_deref() == Some("native.html.v1"))
        || !facets
            .iter()
            .any(|(k, v)| k == "app_package" && v.as_deref() == Some("true"))
    {
        return Err(invalid(
            "source updates require an existing native.html.v1 app_package=true artifact",
        ));
    }
    let shared: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal!=? AND status!='removed' AND json_extract(row_json,'$.artifact_id')=?)")
        .bind(actor).bind(artifact).fetch_one(&mut *conn).await?;
    if shared {
        return Err(invalid("shared app updates are not supported: another principal has an active install of this artifact"));
    }
    let packages: Vec<String> = sqlx::query_scalar("SELECT package FROM kernel_app_installs WHERE principal=? AND status!='removed' AND json_extract(row_json,'$.artifact_id')=?")
        .bind(actor).bind(artifact).fetch_all(&mut *conn).await?;
    // Catalogue membership is live policy, not an input to historical replay.
    let catalog = if before == i64::MAX {
        crate::mcp::tools::alpha_tabs::install_link::packages()
    } else {
        Vec::new()
    };
    if allow_initial && packages.is_empty() {
        // A removed install is not a fresh source. Preserve the old removal
        // boundary rather than letting publication resurrect its authority.
        if never_installed_on(conn, artifact).await?
            && package.is_none_or(|p| !catalog.iter().any(|reserved| reserved == p))
        {
            return Ok(());
        }
    }
    if packages.is_empty()
        || packages.iter().any(|p| catalog.contains(p))
        || package.is_some_and(|p| !packages.iter().any(|existing| existing == p))
    {
        return Err(invalid("source updates require the owner's existing custom package and artifact; catalogue packages are not supported"));
    }
    Ok(())
}

pub(super) fn attestation(
    artifact: &str,
    event: &str,
    revision: &str,
    body: &str,
) -> Result<Value> {
    let html = crate::artifact_html::validate_cached_with_limit(
        body,
        crate::artifact_html::body_limit_for_package_marker(Some("true")),
    )
    .map_err(|e| {
        invalid(&format!(
            "HTML source validation refused [{}]: {}",
            e.code, e.message
        ))
    })?;
    html.require_available_kit().map_err(|e| invalid(e.code))?;
    // Named artifact inputs/grants need their own publication lane.
    if !html.artifact_ports.is_empty() || !html.capability_requests.is_empty() {
        return Err(invalid("personal app source publication does not support named artifact inputs or capability grants"));
    }
    Ok(serde_json::to_value(
        crate::mcp::tools::artifacts::artifact_source_attestation_payload(
            artifact,
            event,
            revision,
            body,
            json!({"runtime":"native.html.v1","artifact_ports":html.artifact_ports,"imports":[],
            "module_inputs":{},"capability_requests":html.capability_requests,
            "interactions":html.interactions,"diagnostics":html.diagnostics}),
        )?,
    )?)
}

pub(crate) async fn publish_on(
    db: &Db,
    conn: &mut SqliteConnection,
    acts: &mut crate::act::ActAllocation,
    actor: &str,
    artifact: &str,
) -> Result<()> {
    require_owner_on(conn, actor, artifact, None).await?;
    let (revision, raw): (String,String) = sqlx::query_as("SELECT id,payload FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' ORDER BY seq DESC LIMIT 1")
        .bind(artifact).fetch_one(&mut *conn).await?;
    let body: Value = serde_json::from_str(&raw)?;
    let body = string(&body, "body")?;
    let id = Uuid::new_v4().to_string();
    let initial = never_installed_on(conn, artifact).await?;
    // Format 1 keeps its existing-install replay semantics. Format 2 admits
    // an owned, never-installed source; execution still requires fresh Add.
    let payload = json!({"format":if initial {2} else {1},"source_revision":revision,"attestation":attestation(artifact,&id,&revision,body)?});
    crate::store::append_with_event_id_on(
        db,
        conn,
        id,
        AppendSpec {
            record_id: artifact.into(),
            event_type: PUBLISHED.into(),
            actor: Some(actor.into()),
            payload,
        },
        acts,
    )
    .await?;
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND payload IS ? AND actor IS ? AND act IS ?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(PUBLISHED).bind(&event.payload).bind(&event.actor).bind(event.act).fetch_one(&mut *conn).await?;
    if !logged || event.event_type != PUBLISHED {
        return Err(invalid("source attestation is not a retained host outcome"));
    }
    let p: Value = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("source publisher missing"))?;
    if p["format"] == 2 {
        require_owner_with_initial_before_on(
            conn,
            actor,
            &event.record_id,
            None,
            event.local_seq,
            true,
        )
        .await?;
    } else {
        require_owner_before_on(conn, actor, &event.record_id, None, event.local_seq).await?;
    }
    let revision = string(&p, "source_revision")?;
    let (id, body, body_actor, act): (String, String, Option<String>, Option<i64>) = sqlx::query_as("SELECT id,json_extract(payload,'$.body'),actor,act FROM content_events WHERE record_id=? AND type='kernel.body_set.v1' AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(&event.record_id).bind(event.local_seq).fetch_one(&mut *conn).await?;
    if id != revision || body_actor.as_deref() != Some(actor) || act.is_none() || act != event.act {
        return Err(invalid(
            "native source attestation requires the owner's same-transaction body revision",
        ));
    }
    verify_attestation(&p, &event.record_id, &event.id, revision, &body)?;
    // Publication is source authority only. The activated artifact closure must
    // remain untouched; app execution switches through guarded install consent.

    Ok(())
}

/// Verify recorded compiler evidence without rerunning today's HTML validator,
/// kit availability or catalogue. Optional compiler fields retain their recorded
/// shape, as in the frozen closure verifier.
pub(super) fn verify_attestation(
    p: &Value,
    artifact: &str,
    event: &str,
    revision: &str,
    body: &str,
) -> Result<()> {
    let attested = &p["attestation"];
    let descriptor = &attested["artifact_source"];
    let compiler = json!({"runtime":"native.html.v1", "artifact_ports":descriptor["artifact_ports"],
        "imports":descriptor["imports"],"module_inputs":descriptor["module_inputs"],
        "capability_requests":descriptor["capability_requests"],
        "interactions":descriptor.get("interactions").cloned().unwrap_or(json!([])),
        "diagnostics":descriptor.get("write_diagnostics").cloned().unwrap_or(json!([]))});
    let mut expected = crate::mcp::tools::artifacts::artifact_source_attestation_payload(
        artifact, event, revision, body, compiler,
    )?;
    for field in ["interactions", "write_diagnostics"] {
        if descriptor.get(field).is_none() {
            expected
                .artifact_source
                .as_object_mut()
                .unwrap()
                .remove(field);
        }
    }
    expected.attestation_sha256 =
        crate::mcp::tools::artifacts::mdx_sha256_for_projection(&expected.artifact_source);
    if (p["format"] != 1 && p["format"] != 2)
        || descriptor["artifact_ports"] != json!({})
        || descriptor["capability_requests"] != json!([])
        || serde_json::to_value(expected)? != *attested
    {
        return Err(invalid("native source attestation mismatch"));
    }
    Ok(())
}

/// A body can advance beyond its activated closure only through retained host
/// publication. Ordinary unactivated body edits still fail closed in render.
pub(crate) async fn published_body_on(
    conn: &mut SqliteConnection,
    artifact: &str,
    body_seq: i64,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events p JOIN content_events b ON b.id=json_extract(p.payload,'$.source_revision') AND b.record_id=p.record_id WHERE p.record_id=? AND p.type IN (?,?,?) AND b.seq=? AND b.type='kernel.body_set.v1' AND b.seq<p.seq)")
        .bind(artifact).bind(PUBLISHED).bind(catalog::PUBLISHED).bind(materialized::MATERIALIZED).bind(body_seq).fetch_one(conn).await?)
}

/// A prepare-time pin is read-only. The accepted install records its binding to
/// package/version/declaration and retains those exact bytes for later replay.
pub(crate) async fn native_pin_on(
    conn: &mut SqliteConnection,
    request: &InstallRequest,
) -> Result<Option<(Value, String, i64)>> {
    crate::mcp::tools::alpha_tabs::require_package(&request.package)?;
    crate::mcp::tools::alpha_tabs::require_version(&request.version)?;
    let row: Option<(String,String,String,String,i64,String)> = sqlx::query_as("SELECT json_extract(e.payload,'$.source_revision'),json_extract(b.payload,'$.body'),e.payload,e.id,e.seq,e.type FROM content_events e JOIN content_events b ON b.id=json_extract(e.payload,'$.source_revision') AND b.record_id=e.record_id AND b.type='kernel.body_set.v1' AND b.seq<e.seq WHERE e.record_id=? AND e.type IN (?,?,?) AND (?='' OR json_extract(e.payload,'$.source_revision')=?) ORDER BY e.seq DESC LIMIT 1")
        .bind(&request.artifact_id).bind(PUBLISHED).bind(catalog::PUBLISHED).bind(materialized::MATERIALIZED).bind(&request.source_revision).bind(&request.source_revision).fetch_optional(&mut *conn).await?;
    let Some((revision, body, raw, id, seq, kind)) = row else {
        // A workspace shelf source carries its evidence on the shelf aggregate,
        // not on the artifact record.
        let Some(shared) =
            shelf::verified_source_on(conn, &request.artifact_id, &request.source_revision).await?
        else {
            return Ok(None);
        };
        if shared.package != request.package
            || shared.version != request.version
            || shared.declaration != request.declaration
        {
            return Ok(None);
        }
        return pin_from(request, &request.source_revision, shared.body, shared.seq);
    };
    let published: Value = serde_json::from_str(&raw)?;
    if kind == catalog::PUBLISHED || kind == materialized::MATERIALIZED {
        let declaration = if kind == materialized::MATERIALIZED {
            materialized::verify(&published, &request.artifact_id, &id, &revision, &body)?
        } else {
            catalog::verify(&published, &request.artifact_id, &id, &revision, &body)?
        };
        if published["entry"]["package"] != request.package
            || published["entry"]["version"] != request.version
            || declaration != request.declaration
        {
            return Ok(None);
        }
    } else {
        verify_attestation(&published, &request.artifact_id, &id, &revision, &body)?;
    }
    pin_from(request, &revision, body, seq)
}

fn pin_from(
    request: &InstallRequest,
    revision: &str,
    body: String,
    seq: i64,
) -> Result<Option<(Value, String, i64)>> {
    if !declarations::source_supported(&request.declaration) {
        return Err(invalid("unsupported app declaration"));
    }
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&request.declaration)?;
    let bundle = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&body);
    let digest = crate::mcp::tools::alpha_tabs::alpha_tab_digest(
        &bundle,
        &declaration_digest,
        "native.html.v1",
    );
    let row = json!({"package":request.package,"version":request.version,"digest":digest,"artifact_id":request.artifact_id,
        "consented_source_revision":revision,"declaration_digest":declaration_digest,"consented_declaration":request.declaration.to_string()});
    Ok(Some((source_pin(&row, &body)?, body, seq)))
}

pub(crate) async fn is_native_on(
    conn: &mut SqliteConnection,
    artifact: &str,
    revision: &str,
) -> Result<bool> {
    let published: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type IN (?,?,?) AND json_extract(payload,'$.source_revision')=?)")
        .bind(artifact).bind(PUBLISHED).bind(catalog::PUBLISHED).bind(materialized::MATERIALIZED).bind(revision).fetch_one(&mut *conn).await?;
    // A workspace shelf source is a native, host-attested pin too.
    Ok(published || shelf::is_source_on(conn, artifact, revision).await?)
}

/// Only personal publication admits members. Catalogue publication and
/// materialization retain workspace-owner footing for their native pins.
pub(crate) async fn require_update_footing_on(
    conn: &mut SqliteConnection,
    caller: &crate::mcp::registry::Caller,
    artifact: &str,
    revision: &str,
) -> Result<()> {
    if caller.counter_footing().is_owner() && caller.host_asserted_app().is_none() {
        return Ok(());
    }
    // A shelf pin is consented to by each member for themself, view-only
    // members included. It is a human act only: apps never consent.
    if shelf::is_source_on(conn, artifact, revision).await? {
        if caller.host_asserted_app().is_some() {
            return Err(Error::auth("app callers cannot consent to workspace apps"));
        }
        return Ok(());
    }
    if !caller.can_update_personal_app() {
        return Err(Error::auth(
            "personal app updates require an eligible workspace member",
        ));
    }
    let personal: bool = sqlx::query_scalar(
        "SELECT COUNT(*) > 0 AND COALESCE(MIN(type=?),0)
         FROM content_events WHERE record_id=? AND json_extract(payload,'$.source_revision')=?
           AND type IN (?,?,?)",
    )
    .bind(PUBLISHED)
    .bind(artifact)
    .bind(revision)
    .bind(PUBLISHED)
    .bind(catalog::PUBLISHED)
    .bind(materialized::MATERIALIZED)
    .fetch_one(conn)
    .await?;
    if !personal {
        return Err(Error::auth("app updates require workspace-owner footing"));
    }
    Ok(())
}

/// Dispatch explicit catalog authority independently of the generic custom
/// publication refusal. Historical callers use the preceding projected state.
pub(crate) async fn require_update_owner_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: Option<&str>,
    revision: &str,
    before: i64,
) -> Result<()> {
    // The artifact-owner requirement is lifted for exactly one thing: a pin
    // that is the live entry on this workspace's shelf. The check is the
    // member's own admission plus that liveness; it grants no authority over
    // the shared artifact, anyone else's row, or any other pin.
    if shelf::is_source_on(conn, artifact, revision).await? {
        consent::require_member(conn, actor, before).await?;
        let package = package.ok_or_else(|| invalid("workspace app package missing"))?;
        shelf::require_live_pin_before_on(conn, package, artifact, revision, before).await?;
        return Ok(());
    }
    if materialized::is_materialized_on(conn, artifact, revision).await? {
        return materialized::require_source_before_on(
            conn,
            actor,
            artifact,
            package.ok_or_else(|| invalid("materialized package missing"))?,
            revision,
            before,
        )
        .await;
    }
    let published: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=? AND seq<? AND json_extract(payload,'$.entry.package')=? AND json_extract(payload,'$.source_revision')=?)")
        .bind(artifact).bind(catalog::PUBLISHED).bind(before).bind(package).bind(revision).fetch_one(&mut *conn).await?;
    if published {
        catalog::require_source_owner_before_on(
            conn,
            actor,
            artifact,
            package.ok_or_else(|| invalid("catalog package missing"))?,
            revision,
            before,
        )
        .await
    } else {
        let initial: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=? AND seq<? AND json_extract(payload,'$.source_revision')=? AND json_extract(payload,'$.format')=2)")
            .bind(artifact).bind(PUBLISHED).bind(before).bind(revision).fetch_one(&mut *conn).await?;
        if initial {
            require_owner_with_initial_before_on(conn, actor, artifact, package, before, true).await
        } else {
            require_owner_before_on(conn, actor, artifact, package, before).await
        }
    }
}
pub(crate) async fn require_update_owner_on(
    conn: &mut SqliteConnection,
    actor: &str,
    artifact: &str,
    package: Option<&str>,
    revision: &str,
) -> Result<()> {
    require_update_owner_before_on(conn, actor, artifact, package, revision, i64::MAX).await
}
