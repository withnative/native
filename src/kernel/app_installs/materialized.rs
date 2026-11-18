//! Personal materialization of a trusted catalog update. The predecessor's
//! artifact is never edited; only a fresh, account-only source can be rebound.
use super::*;
use crate::mcp::tools::catalog_assets::{
    validate_catalog, verify_retained_payload, MaterializeRequest,
};

#[cfg(feature = "v2-kernel-probe")]
use crate::mcp::tools::catalog_assets::CatalogAssets;

pub(crate) const MATERIALIZED: &str = "kernel.app_catalog_update_materialized.v1";

async fn installed_on(
    conn: &mut SqliteConnection,
    actor: &str,
    package: &str,
) -> Result<(String, Value, Value)> {
    let (generation,raw,status):(String,String,String)=sqlx::query_as("SELECT generation,row_json,status FROM kernel_app_installs WHERE principal=? AND package=?")
        .bind(actor).bind(package).fetch_optional(&mut *conn).await?.ok_or_else(|| invalid("catalog materialization requires an existing install"))?;
    if status != "installed" {
        return Err(invalid(
            "catalog materialization requires an installed predecessor",
        ));
    }
    let row: Value = serde_json::from_str(&raw)?;
    let request = InstallRequest {
        package: package.into(),
        version: string(&row, "version")?.into(),
        digest: string(&row, "digest")?.into(),
        artifact_id: string(&row, "artifact_id")?.into(),
        source_revision: string(&row, "consented_source_revision")?.into(),
        declaration: serde_json::from_str(string(&row, "consented_declaration")?)?,
        reason: "Verify materialization predecessor".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: None,
    };
    let pin = consent::source_on(conn, &request).await?.pin;
    Ok((generation, row, pin))
}

#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn materialize_as(
    db: &Db,
    actor: &str,
    assets: &CatalogAssets,
    request: MaterializeRequest,
) -> Result<Value> {
    if request.reason.trim().is_empty()
        || request.reason.len() > 1024
        || request.idempotency_key.trim().is_empty()
        || request.idempotency_key.len() > 200
    {
        return Err(invalid(
            "materialization requires a reason and bounded idempotency key",
        ));
    }
    let mut tx = begin_write(db.write_pool()).await?;
    require_activated_on(&mut tx).await?;
    consent::require_member(&mut tx, actor, i64::MAX).await?;
    let intent = serde_json::to_value(&request)?;
    // Recover the exact retained identity before allocating any target. Current
    // authority and predecessor continuity are rechecked even on an uncertain retry.
    let prior:Option<(String,String)>=sqlx::query_as("SELECT record_id,payload FROM content_events WHERE type=? AND actor=? AND json_extract(payload,'$.intent.idempotency_key')=? ORDER BY seq DESC LIMIT 1")
        .bind(MATERIALIZED).bind(actor).bind(&request.idempotency_key).fetch_optional(&mut *tx).await?;
    if let Some((target, raw)) = prior {
        let p: Value = serde_json::from_str(&raw)?;
        if p["intent"] != intent {
            return Err(Error::conflict(
                "materialization idempotency key reused for different intent",
            ));
        }
        require_source_before_on(
            &mut tx,
            actor,
            &target,
            &request.package,
            string(&p, "source_revision")?,
            i64::MAX,
        )
        .await?;
        require_predecessor_on(&mut tx, actor, &p).await?;
        return Ok(p["result"].clone());
    }
    let (generation, row, old_pin) = installed_on(&mut tx, actor, &request.package).await?;
    if generation != request.expected_install_event_id
        || row["artifact_id"] != request.predecessor_artifact_id
    {
        return Err(Error::conflict(
            "materialization install predecessor changed",
        ));
    }
    if consent::pending_on(&mut tx, actor, &request.package)
        .await?
        .is_some()
    {
        return Err(Error::conflict(
            "catalog materialization refuses a competing pending update",
        ));
    }
    let (entry, bytes, body) = assets.select(&request.package, &request.version)?;
    let payload: Value = serde_json::from_slice(&bytes)?;
    if !declarations::source_supported(&payload["declaration"]) {
        return Err(invalid("catalog declaration unsupported on v2"));
    }
    let target = Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        &serde_json::to_vec(&(MATERIALIZED, actor, &request.idempotency_key))?,
    )
    .to_string();
    let revision = Uuid::new_v4().to_string();
    let event_id = Uuid::new_v4().to_string();
    let attestation = sources::attestation(&target, &event_id, &revision, &body)?;
    let carrier = crate::v2_standard::v1_compat::v1_carrier_for("Document", "artifact");
    let fields = crate::v2_standard::v1_compat::compat_fields(
        "Document",
        "artifact",
        entry["title"].as_str(),
        None,
        None,
    );
    // The compatibility carrier supports structured values and therefore
    // requires its duplicate-aware raw JSON input seam, as ordinary creation does.
    let raw_fields = serde_json::to_string(&fields)?;
    let mut acts = crate::act::ActAllocation::new();
    create_input_admitted_in(
        db,
        &mut tx,
        &mut acts,
        actor,
        carrier.family(),
        carrier.kind(),
        FieldInput::Raw(&raw_fields),
        crate::events::KERNEL_ROOT_ID,
        None,
        true,
        Some(&target),
        None,
        None,
    )
    .await?;
    account_only_record_in(db, &mut tx, &mut acts, actor, &target).await?;
    // These fixed host events carry no caller-authored facets or metadata.
    for (key, value) in [("runtime", "native.html.v1"), ("app_package", "true")] {
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: target.clone(),
                event_type: "kernel.facet_observed.v1".into(),
                actor: Some(actor.into()),
                payload: json!({"key":key,"value":value,"as_of":chrono::Utc::now().to_rfc3339()}),
            },
            &mut acts,
        )
        .await?;
    }
    crate::store::append_with_event_id_on(
        db,
        &mut tx,
        revision.clone(),
        AppendSpec {
            record_id: target.clone(),
            event_type: "kernel.body_set.v1".into(),
            actor: Some(actor.into()),
            payload: json!({"body":body}),
        },
        &mut acts,
    )
    .await?;
    let result = json!({"artifact_id":target,"source_revision":revision,"package":request.package,"version":request.version,"body_digest":entry["body_digest"],"digest":entry["digest"],"declaration":payload["declaration"],"expected_install_event_id":generation,"predecessor_artifact_id":request.predecessor_artifact_id,"adoption":"requires_person_preview_adopt"});
    let retained = json!({"format":1,"principal":actor,"source_revision":revision,"predecessor_generation":generation,"predecessor_pin":old_pin,"intent":intent,"result":result,"catalog":assets.catalog,"entry":entry,"payload_text":String::from_utf8(bytes).map_err(|_|invalid("catalog payload encoding"))?,"attestation":attestation});
    crate::store::append_with_event_id_on(
        db,
        &mut tx,
        event_id,
        AppendSpec {
            record_id: target,
            event_type: MATERIALIZED.into(),
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
    target: &str,
    event: &str,
    revision: &str,
    body: &str,
) -> Result<Value> {
    validate_catalog(&p["catalog"])?;
    let entry = &p["entry"];
    if p["format"] != 1
        || !p["catalog"]["entries"]
            .as_array()
            .expect("validated catalog")
            .contains(entry)
        || p["source_revision"] != revision
    {
        return Err(invalid("materialization catalog witness mismatch"));
    }
    let bytes = string(p, "payload_text")?.as_bytes();
    verify_retained_payload(entry, bytes, body)?;
    sources::verify_attestation(p, target, event, revision, body)?;
    let intent: MaterializeRequest = serde_json::from_value(p["intent"].clone())?;
    let principal = string(p, "principal")?;
    let expected_target = Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        &serde_json::to_vec(&(MATERIALIZED, principal, &intent.idempotency_key))?,
    )
    .to_string();
    let declaration = serde_json::from_slice::<Value>(bytes)?["declaration"].clone();
    let result = json!({"artifact_id":target,"source_revision":revision,"package":intent.package,"version":intent.version,"body_digest":entry["body_digest"],"digest":entry["digest"],"declaration":declaration,"expected_install_event_id":intent.expected_install_event_id,"predecessor_artifact_id":intent.predecessor_artifact_id,"adoption":"requires_person_preview_adopt"});
    if target != expected_target
        || intent.package != entry["package"]
        || intent.version != entry["version"]
        || intent.expected_install_event_id != p["predecessor_generation"]
        || intent.predecessor_artifact_id != p["predecessor_pin"]["artifact_id"]
        || p["predecessor_pin"]["package"] != entry["package"]
        || intent.predecessor_artifact_id == target
        || p["result"] != result
        || intent.reason.trim().is_empty()
        || intent.reason.len() > 1024
        || intent.idempotency_key.trim().is_empty()
        || intent.idempotency_key.len() > 200
    {
        return Err(invalid("materialization identity/intent/result mismatch"));
    }
    Ok(declaration)
}

async fn evidence_on(
    conn: &mut SqliteConnection,
    target: &str,
    revision: &str,
    before: i64,
) -> Result<(Value, String, String, i64)> {
    let (raw,event,seq,body):(String,String,i64,String)=sqlx::query_as("SELECT e.payload,e.id,e.seq,json_extract(b.payload,'$.body') FROM content_events e JOIN content_events b ON b.id=json_extract(e.payload,'$.source_revision') AND b.record_id=e.record_id AND b.type='kernel.body_set.v1' AND b.seq<e.seq WHERE e.record_id=? AND e.type=? AND json_extract(e.payload,'$.source_revision')=? AND e.seq<?")
        .bind(target).bind(MATERIALIZED).bind(revision).bind(before).fetch_optional(&mut *conn).await?.ok_or_else(||invalid("materialization source witness missing"))?;
    let p: Value = serde_json::from_str(&raw)?;
    verify(&p, target, &event, revision, &body)?;
    Ok((p, event, body, seq))
}

async fn target_on(
    conn: &mut SqliteConnection,
    actor: &str,
    target: &str,
    revision: &str,
) -> Result<()> {
    let record = read_record_unchecked_on(conn, actor, target)
        .await?
        .ok_or_else(|| invalid("materialized target missing"))?;
    if record.owner_id.as_deref() != Some(actor)
        || !is_artifact_on(conn, &record).await?
        || record.home_id != v1_import_home_id(target)
    {
        return Err(invalid("materialized target must remain owner-private"));
    }
    let entries:Vec<(String,String,String,String)>=sqlx::query_as("SELECT subject_kind,subject_id,effect,capability FROM kernel_policy_entries WHERE root_id=?")
        .bind(&record.home_id).fetch_all(&mut *conn).await?;
    let owner: Option<String> =
        sqlx::query_scalar("SELECT owner_id FROM kernel_roots WHERE root_id=?")
            .bind(&record.home_id)
            .fetch_one(&mut *conn)
            .await?;
    let facets:i64=sqlx::query_scalar("SELECT count(*) FROM kernel_facets WHERE record_id=? AND ((key='runtime' AND value='native.html.v1') OR (key='app_package' AND value='true'))").bind(target).fetch_one(&mut *conn).await?;
    // Retained projection checks also compile in default test/replay builds;
    // do not depend on the feature-gated current-read body-evidence module.
    let current_body: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_record_bodies b JOIN content_events e ON e.seq=b.event_seq AND e.record_id=b.record_id WHERE b.record_id=? AND e.id=? AND e.type='kernel.body_set.v1' AND b.body IS json_extract(e.payload,'$.body'))")
        .bind(target).bind(revision).fetch_one(&mut *conn).await?;
    let shared:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal!=? AND status!='removed' AND json_extract(row_json,'$.artifact_id')=?)").bind(actor).bind(target).fetch_one(&mut *conn).await?;
    if entries
        != vec![(
            "account".into(),
            actor.into(),
            "allow".into(),
            "manage".into(),
        )]
        || owner.as_deref() != Some(actor)
        || facets != 2
        || !current_body
        || shared
    {
        return Err(invalid(
            "materialized target policy/body/install witness changed",
        ));
    }
    Ok(())
}

async fn require_predecessor_on(conn: &mut SqliteConnection, actor: &str, p: &Value) -> Result<()> {
    let package = string(&p["entry"], "package")?;
    let (generation, _, pin) = installed_on(conn, actor, package).await?;
    if p["principal"] != actor
        || p["predecessor_generation"] != generation
        || p["predecessor_pin"] != pin
    {
        return Err(Error::conflict("materialization predecessor pin changed"));
    }
    Ok(())
}

pub(crate) async fn is_materialized_on(
    conn: &mut SqliteConnection,
    target: &str,
    revision: &str,
) -> Result<bool> {
    Ok(sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE record_id=? AND type=? AND json_extract(payload,'$.source_revision')=?)").bind(target).bind(MATERIALIZED).bind(revision).fetch_one(conn).await?)
}

/// Current reviews and retained replay use exact source identity. Once adopted,
/// the same pin is allowed for an idempotent adoption receipt, never a new rebind.
pub(crate) async fn require_source_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    target: &str,
    package: &str,
    revision: &str,
    before: i64,
) -> Result<()> {
    consent::require_member(conn, actor, before).await?;
    let (p, _, _, _) = evidence_on(conn, target, revision, before).await?;
    if p["principal"] != actor || p["entry"]["package"] != package {
        return Err(invalid(
            "materialization belongs to another principal or package",
        ));
    }
    target_on(conn, actor, target, revision).await?;
    let (generation, row, pin) = installed_on(conn, actor, package).await?;
    if generation == p["predecessor_generation"] && pin == p["predecessor_pin"] {
        return Ok(());
    }
    if row["artifact_id"] == target
        && row["consented_source_revision"] == revision
        && pin["digest"] == p["entry"]["digest"]
    {
        return Ok(());
    }
    Err(Error::conflict("materialization predecessor changed"))
}

pub(crate) async fn require_rebind_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    request: &InstallRequest,
    before: i64,
) -> Result<()> {
    let (p, _, _, _) =
        evidence_on(conn, &request.artifact_id, &request.source_revision, before).await?;
    require_source_before_on(
        conn,
        actor,
        &request.artifact_id,
        &request.package,
        &request.source_revision,
        before,
    )
    .await?;
    require_predecessor_on(conn, actor, &p).await?;
    if consent::pending_before_on(conn, actor, &request.package, before)
        .await?
        .is_some()
    {
        return Err(Error::conflict(
            "materialized rebind refuses a competing pending update",
        ));
    }
    if request.expected_install_event_id.as_deref() != p["predecessor_generation"].as_str()
        || p["entry"]["version"] != request.version
        || p["entry"]["digest"] != request.digest
    {
        return Err(invalid("materialized rebind pin mismatch"));
    }
    Ok(())
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE id=? AND seq=? AND record_id=? AND type=? AND actor IS ? AND act IS ? AND payload IS ?)").bind(&event.id).bind(event.local_seq).bind(&event.record_id).bind(MATERIALIZED).bind(&event.actor).bind(event.act).bind(&event.payload).fetch_one(&mut *conn).await?;
    if !logged || event.event_type != MATERIALIZED {
        return Err(invalid("materialization is not a retained host outcome"));
    }
    let p: Value = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("materialization principal missing"))?;
    consent::require_member(conn, actor, event.local_seq).await?;
    require_predecessor_on(conn, actor, &p).await?;
    // A competing stage at the materialization frontier would make a second
    // target ambiguous. Later stages are intentionally not replay inputs.
    if consent::pending_before_on(
        conn,
        actor,
        string(&p["entry"], "package")?,
        event.local_seq,
    )
    .await?
    .is_some()
    {
        return Err(invalid(
            "materialization has a competing pending predecessor",
        ));
    }
    let revision = string(&p, "source_revision")?;
    target_on(conn, actor, &event.record_id, revision).await?;
    let (body,body_actor,body_act):(String,Option<String>,Option<i64>)=sqlx::query_as("SELECT json_extract(payload,'$.body'),actor,act FROM content_events WHERE id=? AND record_id=? AND type='kernel.body_set.v1' AND seq<?").bind(revision).bind(&event.record_id).bind(event.local_seq).fetch_one(&mut *conn).await?;
    let creations:i64=sqlx::query_scalar("SELECT count(*) FROM content_events WHERE record_id=? AND type='kernel.record_created.v1' AND actor=? AND act=? AND seq<?").bind(&event.record_id).bind(actor).bind(event.act).bind(event.local_seq).fetch_one(&mut *conn).await?;
    if creations != 1
        || body_actor.as_deref() != Some(actor)
        || body_act.is_none()
        || body_act != event.act
    {
        return Err(invalid(
            "materialization requires same-act owner creation/body",
        ));
    }
    verify(&p, &event.record_id, &event.id, revision, &body)?;
    Ok(())
}
