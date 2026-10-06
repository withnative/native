//! Closed, snapshot-current PRIMARY SQLite AlphaInstall resolver.
//! No wire emitter or authority constructor; every page proves current source.
use super::*;
use crate::control::{AlphaTabAdoptV2Payload, ControlEventRow};
use serde_json::Value;
mod predecessor;

fn uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|u| u.to_string() == value)
}
pub(in crate::body_read) fn package_valid(value: &str) -> bool {
    value.len() <= 128
        && value.split('.').count() >= 2
        && value.split('.').all(|p| {
            !p.is_empty()
                && p.len() <= 32
                && !p.starts_with('-')
                && !p.ends_with('-')
                && p.bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
        })
}
fn version(value: &str) -> bool {
    value.len() <= 32
        && value.split('.').count() == 3
        && value
            .split('.')
            .all(|p| !p.is_empty() && p.len() <= 8 && p.bytes().all(|c| c.is_ascii_digit()))
}
fn tuple(purpose: &str, members: &[&str]) -> Result<String> {
    let mut values = vec!["records.body.read.v1", "1", purpose, "AlphaInstall"];
    values.extend_from_slice(members);
    let bytes = serde_json::to_vec(&values).map_err(|_| Failure::SourceIntegrity)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

/// Store the ACTUAL worker JoinHandle<()> before awaiting domain output.
/// Receiver loss never joins/detaches/clears that registered physical handle.
pub(super) async fn cpu<F>(slot: &mut CpuSlot, budget: &Budget, work: F) -> Result<CpuOutput>
where
    F: FnOnce() -> Result<CpuOutput> + Send + 'static,
{
    budget.stop()?;
    if slot.handles.len() >= CPU_STAGES {
        return Err(Failure::ProvenanceWork);
    }
    let cancel = budget.cancelled.clone();
    let steps = budget.steps.clone();
    let deadline = budget.deadline;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let check = || {
            if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
                Err(Failure::Timeout)
            } else if steps.load(Ordering::SeqCst) >= VM {
                Err(Failure::VmWork)
            } else {
                Ok(())
            }
        };
        let result = check().and_then(|()| work()).and_then(|output| {
            check()?;
            Ok(output)
        });
        let _ = sender.send(result);
    });
    slot.handles.push(worker);
    let result = receiver.await.map_err(|_| Failure::Engine)?;
    budget.stop()?;
    result
}

// Identifiers/columns are static engine projections, never request SQL. The
// metadata pass rejects BLOB/overflow before hydration under the same snapshot.
type Field = (&'static str, i64, bool);
const INSTALL: &[Field] = &[
    ("account_id", 256, false),
    ("package", 128, false),
    ("version", 32, false),
    ("digest", 71, false),
    ("artifact_id", 256, false),
    ("consented_source_revision", 256, false),
    ("declaration_digest", 64, false),
    ("consented_declaration", PROVENANCE as i64, false),
    ("adoption", 32, false),
    ("request", 2000, true),
    ("status", 32, false),
    ("event_id", 36, false),
    ("updated_at", 128, false),
    ("body_read_admission_event_id", 36, true),
];
const CONTROL: &[Field] = &[
    ("id", 36, false),
    ("idempotency_key", 1024, false),
    ("type", 64, false),
    ("aggregate_kind", 64, false),
    ("aggregate_id", 512, false),
    ("actor", 256, false),
    ("reason", 4096, false),
    ("payload", PROVENANCE as i64, false),
    ("run_key", 1024, true),
    ("created_at", 128, false),
];
async fn row(
    snapshot: &mut ReadSnapshot<'_>,
    table: &'static str,
    predicate: &'static str,
    binds: &[&str],
    fields: &[Field],
    extra: &'static str,
) -> Result<Option<sqlx::sqlite::SqliteRow>> {
    let sizes = fields
        .iter()
        .map(|(c, _, _)| format!("typeof({c}),octet_length({c})"))
        .collect::<Vec<_>>()
        .join(",");
    snapshot.budget.sql()?;
    let sql = format!("SELECT {sizes} FROM {table} WHERE {predicate}");
    let mut query = sqlx::query(&sql);
    for b in binds {
        query = query.bind(*b);
    }
    let Some(metadata) = query
        .fetch_optional(&mut *snapshot.transaction)
        .await
        .map_err(|e| snapshot.map_sql(e))?
    else {
        return Ok(None);
    };
    for (i, (_, cap, nullable)) in fields.iter().enumerate() {
        let kind: String = metadata
            .try_get(i * 2)
            .map_err(|_| Failure::SourceIntegrity)?;
        let bytes: Option<i64> = metadata
            .try_get(i * 2 + 1)
            .map_err(|_| Failure::SourceIntegrity)?;
        match (kind.as_str(), bytes) {
            ("null", None) if *nullable => (),
            ("text", Some(n)) if (0..=*cap).contains(&n) => {
                // Reserve copies BEFORE hydration/try_get/serde/frozen/JCS.
                // The full JSON proof allows eight conservative extra full
                // representations; retained source parsing allows two extras.
                let copies = if fields[i].0 == "consented_declaration"
                    || (table == "control_events" && fields[i].0 == "payload")
                {
                    9
                } else if table == "content_events" && fields[i].0 == "payload" {
                    3
                } else {
                    2
                };
                snapshot
                    .budget
                    .charge(n.checked_mul(copies).ok_or(Failure::ProvenanceWork)?, true)?;
            }
            _ => return Err(Failure::SourceIntegrity),
        }
    }
    snapshot.budget.sql()?;
    let cols = fields
        .iter()
        .map(|(c, _, _)| *c)
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!("SELECT {cols}{extra} FROM {table} WHERE {predicate}");
    let mut query = sqlx::query(&sql);
    for b in binds {
        query = query.bind(*b);
    }
    query
        .fetch_optional(&mut *snapshot.transaction)
        .await
        .map_err(|e| snapshot.map_sql(e))
}
fn source_text(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<String> {
    text(row, field).map_err(|_| Failure::SourceIntegrity)
}
fn optional_text(row: &sqlx::sqlite::SqliteRow, field: &str) -> Result<Option<String>> {
    optional(row, field).map_err(|_| Failure::SourceIntegrity)
}
async fn control(snapshot: &mut ReadSnapshot<'_>, id: &str) -> Result<ControlEventRow> {
    if !uuid(id) {
        return Err(Failure::SourceIntegrity);
    }
    snapshot.budget.event()?;
    let r = row(
        snapshot,
        "control_events",
        "id=?",
        &[id],
        CONTROL,
        ",seq,schema_version,act",
    )
    .await?
    .ok_or(Failure::SourceIntegrity)?;
    let event = ControlEventRow {
        seq: r.try_get("seq").map_err(|_| Failure::SourceIntegrity)?,
        id: source_text(&r, "id")?,
        idempotency_key: source_text(&r, "idempotency_key")?,
        event_type: source_text(&r, "type")?,
        schema_version: r
            .try_get("schema_version")
            .map_err(|_| Failure::SourceIntegrity)?,
        aggregate_kind: source_text(&r, "aggregate_kind")?,
        aggregate_id: source_text(&r, "aggregate_id")?,
        actor: source_text(&r, "actor")?,
        run_key: optional_text(&r, "run_key")?,
        reason: source_text(&r, "reason")?,
        payload: source_text(&r, "payload")?,
        created_at: source_text(&r, "created_at")?,
        act: r.try_get("act").map_err(|_| Failure::SourceIntegrity)?,
    };
    if event.seq <= 0
        || event.seq as u64 > super::super::JS_SAFE
        || event.schema_version != 1
        || event
            .act
            .is_some_and(|a| a < 0 || a as u64 > super::super::JS_SAFE)
        || event.id != id
    {
        return Err(Failure::SourceIntegrity);
    }
    predecessor::envelope(&event)?;
    Ok(event)
}

// Raw authenticated SAME-snapshot facts, not hashes decoded from token tags.
// These structs intentionally have no Clone/authority constructors.
#[derive(serde::Serialize)]
pub(super) struct MixedPin {
    pub(super) package: String,
    pub(super) version: String,
    pub(super) digest: String,
    pub(super) artifact_id: String,
    pub(super) source_revision: String,
    pub(super) declaration_digest: String,
}
#[derive(serde::Serialize)]
pub(super) struct MixedSource {
    pub(super) event_id: String,
    pub(super) bundle_sha256: String,
    pub(super) body_digest: String,
}
#[derive(serde::Serialize)]
pub(super) struct MixedSourceBinding {
    pub(super) pin: MixedPin,
    pub(super) install_event_id: String,
    pub(super) body_admission_event_id: String,
    pub(super) source: MixedSource,
}
pub(super) struct CurrentAlphaProof {
    pub(super) binding: ResolvedSource,
    pub(super) body: String,
    pub(super) bundle: String,
    pub(super) mixed_binding: Option<MixedSourceBinding>,
}
pub(super) async fn resolve_current(
    snapshot: &mut ReadSnapshot<'_>,
    package: &str,
    handle: &str,
    slot: &mut CpuSlot,
) -> Result<CurrentAlphaProof> {
    resolve_current_profile(snapshot, package, handle, slot, false).await
}
pub(super) async fn resolve_current_mixed(
    snapshot: &mut ReadSnapshot<'_>,
    package: &str,
    handle: &str,
    slot: &mut CpuSlot,
) -> Result<CurrentAlphaProof> {
    resolve_current_profile(snapshot, package, handle, slot, true).await
}
async fn resolve_current_profile(
    snapshot: &mut ReadSnapshot<'_>,
    package: &str,
    handle: &str,
    slot: &mut CpuSlot,
    mixed: bool,
) -> Result<CurrentAlphaProof> {
    if !package_valid(package) || !uuid(handle) {
        return Err(Failure::SourceIntegrity);
    }
    let viewer = snapshot.viewer.clone();
    let install = row(
        snapshot,
        "alpha_tab_installs",
        "account_id=? AND package=?",
        &[&viewer, package],
        INSTALL,
        ",event_seq",
    )
    .await?
    .ok_or(Failure::SourceIntegrity)?;
    let artifact = source_text(&install, "artifact_id")?;
    let revision = source_text(&install, "consented_source_revision")?;
    if !trusted_input(&artifact)
        || !trusted_input(&revision)
        || source_text(&install, "account_id")? != viewer
        || source_text(&install, "package")? != package
        || !version(&source_text(&install, "version")?)
    {
        return Err(Failure::SourceIntegrity);
    }
    // Current eligible artifact shape before effective View, then proof/scope.
    let source = row(
        snapshot,
        "records",
        "id=?",
        &[&artifact],
        &[
            ("type", 256, false),
            ("kind", 256, true),
            ("deleted_at", 128, true),
        ],
        "",
    )
    .await?
    .ok_or(Failure::SourceIntegrity)?;
    let rt = source_text(&source, "type")?;
    let kind = optional_text(&source, "kind")?;
    if optional_text(&source, "deleted_at")?.is_some()
        || rt != "Document"
        || !snapshot
            .kind(&rt, kind.as_deref())
            .await?
            .is_some_and(|k| crate::generated::kinds::CoreKind::DocumentArtifact.matches(&k))
        || !snapshot.eligible(&artifact).await?
    {
        return Err(Failure::SourceIntegrity);
    }
    snapshot.budget.sql()?;
    let archived: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM facet_values WHERE record_id=? AND key=?)")
            .bind(&artifact)
            .bind(crate::schema::ARCHIVED_FACET_KEY)
            .fetch_one(&mut *snapshot.transaction)
            .await
            .map_err(|e| snapshot.map_sql(e))?;
    if archived {
        return Err(Failure::SourceIntegrity);
    }
    let member = snapshot.member;
    let capability = crate::authorization::effective_capability_with(
        snapshot,
        crate::authorization::Principal::bound(&viewer, member),
        &artifact,
        false,
    )
    .await
    .map_err(|_| snapshot.budget.stop().err().unwrap_or(Failure::Engine))?;
    if !capability.allows(crate::authorization::Capability::View) {
        return Err(Failure::SourceIntegrity);
    }
    if source_text(&install, "status")? != "installed" {
        return Err(Failure::SourceIntegrity);
    }
    let raw_decl = source_text(&install, "consented_declaration")?;
    let CpuOutput::Declaration(declaration, has_descriptor) =
        cpu(slot, snapshot.budget, move || {
            let value: Value =
                serde_json::from_str(&raw_decl).map_err(|_| Failure::SourceIntegrity)?;
            crate::alpha_tab_body_admission_v1::canonical_declaration(&value)
                .map_err(|_| Failure::SourceIntegrity)?;
            let descriptor = crate::alpha_tab_body_admission_v1::has_body_descriptor(&value)
                .map_err(|_| Failure::SourceIntegrity)?;
            Ok(CpuOutput::Declaration(value, descriptor))
        })
        .await?
    else {
        return Err(Failure::Engine);
    };
    if !has_descriptor {
        return Err(Failure::UndeclaredRead);
    }
    let pointer = optional_text(&install, "body_read_admission_event_id")?;
    let adoption = source_text(&install, "adoption")?;
    if pointer.is_none() || adoption == "caller_asserted" {
        return Err(Failure::AdoptionRequired);
    }
    if !matches!(adoption.as_str(), "shell_auto.v1" | "shell_adopt.v1") {
        return Err(Failure::SourceIntegrity);
    }
    let pointer = pointer.unwrap();
    let latest = source_text(&install, "event_id")?;
    if !uuid(&pointer) || latest != pointer {
        return Err(Failure::SourceIntegrity);
    }
    let event = control(snapshot, &pointer).await?;
    let aggregate = crate::control::alpha_tab_aggregate_id(&viewer, package);
    snapshot.budget.sql()?;
    let actual_latest: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(seq) FROM control_events WHERE aggregate_kind='alpha_tab' AND aggregate_id=?",
    )
    .bind(&aggregate)
    .fetch_one(&mut *snapshot.transaction)
    .await
    .map_err(|e| snapshot.map_sql(e))?;
    if actual_latest != Some(event.seq)
        || install
            .try_get::<i64, _>("event_seq")
            .map_err(|_| Failure::SourceIntegrity)?
            != event.seq
        || event.aggregate_kind != "alpha_tab"
        || event.aggregate_id != aggregate
        || event.actor != viewer
        || source_text(&install, "updated_at")? != event.created_at
        || event.event_type != "alpha_tab.adopted.v2"
    {
        return Err(Failure::SourceIntegrity);
    }
    let CpuOutput::Marker(proof) = cpu(slot, snapshot.budget, move || {
        let payload: AlphaTabAdoptV2Payload = predecessor::decode(&event.payload)?;
        crate::control::validate_alpha_tab_adopt_v2(&event, &payload)
            .map_err(|_| Failure::SourceIntegrity)?;
        Ok(CpuOutput::Marker(Box::new((event, payload))))
    })
    .await?
    else {
        return Err(Failure::Engine);
    };
    let (event, payload) = *proof;
    for (column, expected) in [
        ("account_id", &payload.account_id),
        ("package", &payload.package),
        ("version", &payload.version),
        ("digest", &payload.digest),
        ("artifact_id", &payload.artifact_id),
        (
            "consented_source_revision",
            &payload.consented_source_revision,
        ),
        ("declaration_digest", &payload.declaration_digest),
        ("adoption", &payload.adoption),
    ] {
        if source_text(&install, column)? != *expected {
            return Err(Failure::SourceIntegrity);
        }
    }
    if !super::super::digest(&payload.declaration_digest) {
        return Err(Failure::SourceIntegrity);
    }
    // Exact nearest prior state in this canonical aggregate, not an arbitrary
    // earlier marker; the current v2 must have actually advanced that CAS pin.
    snapshot.budget.sql()?;
    let previous_id:Option<String>=sqlx::query_scalar("SELECT CASE WHEN typeof(id)='text' AND octet_length(id)=36 THEN id END FROM control_events WHERE aggregate_kind='alpha_tab' AND aggregate_id=? AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(&aggregate).bind(event.seq).fetch_optional(&mut *snapshot.transaction).await.map_err(|e|snapshot.map_sql(e))?.flatten();
    if previous_id.as_deref() != Some(&payload.previous_event_id) {
        return Err(Failure::SourceIntegrity);
    }
    let previous = control(snapshot, &payload.previous_event_id).await?;
    let current_request = optional_text(&install, "request")?;
    let CpuOutput::Marker(proof) = cpu(slot, snapshot.budget, move || {
        let extracted = predecessor::extract_reader_predecessor_v1(&previous, &payload.account_id)?;
        let request_matches = extracted.request_matches(&payload, current_request.as_deref());
        let prior = &extracted.pin;
        if previous.seq >= event.seq
            || previous.aggregate_kind != event.aggregate_kind
            || previous.aggregate_id != event.aggregate_id
            || declaration != payload.consented_declaration
            || prior.consented_declaration != payload.consented_declaration
            || prior.account_id != payload.account_id
            || prior.package != payload.package
            || prior.version != payload.version
            || prior.digest != payload.digest
            || prior.artifact_id != payload.artifact_id
            || prior.consented_source_revision != payload.consented_source_revision
            || prior.declaration_digest != payload.declaration_digest
            || !request_matches
        {
            return Err(Failure::SourceIntegrity);
        }
        Ok(CpuOutput::Marker(Box::new((event, payload))))
    })
    .await?
    else {
        return Err(Failure::Engine);
    };
    let (_event, payload) = *proof;
    let runtime = row(
        snapshot,
        "facet_values",
        "record_id=? AND key='runtime'",
        &[&artifact],
        &[("value", 256, false)],
        "",
    )
    .await?
    .ok_or(Failure::SourceIntegrity)?;
    if source_text(&runtime, "value")? != "native.html.v1" {
        return Err(Failure::SourceIntegrity);
    }
    snapshot.budget.event()?;
    let retained=row(snapshot,"content_events","record_id=? AND id=? AND type IN ('record.created','record.updated','receipt.committed.v1')",&[&artifact,&revision],&[("payload",PROVENANCE as i64,false)],"").await?.ok_or(Failure::SourceIntegrity)?;
    let raw = source_text(&retained, "payload")?;
    // Payload hydration + serde representation are charged as provenance. The
    // extracted string moves out of Value; only actual UTF-8 bundle is source.
    let CpuOutput::Json(mut content) = cpu(slot, snapshot.budget, move || {
        let v: Value = serde_json::from_str(&raw).map_err(|_| Failure::SourceIntegrity)?;
        if !v.is_object() {
            return Err(Failure::SourceIntegrity);
        }
        Ok(CpuOutput::Json(v))
    })
    .await?
    else {
        return Err(Failure::Engine);
    };
    let body = content
        .as_object_mut()
        .and_then(|v| v.remove("body"))
        .and_then(|v| match v {
            Value::String(s) => Some(s),
            _ => None,
        })
        .ok_or(Failure::SourceIntegrity)?;
    snapshot.budget.charge(body.len() as i64, false)?;
    let deadline = snapshot.budget.deadline;
    let cancel = snapshot.budget.cancelled.clone();
    let CpuOutput::AlphaBody(body, bundle) = cpu(slot, snapshot.budget, move || {
        let mut h = Sha256::new();
        for chunk in body.as_bytes().chunks(65536) {
            if cancel.load(Ordering::SeqCst) || Instant::now() >= deadline {
                return Err(Failure::Timeout);
            }
            h.update(chunk);
        }
        Ok(CpuOutput::AlphaBody(body, hex::encode(h.finalize())))
    })
    .await?
    else {
        return Err(Failure::Engine);
    };
    if bundle != payload.bundle_sha256
        || payload.runtime != "native.html.v1"
        || crate::alpha_tab_body_admission_v1::install_digest(
            &bundle,
            &payload.declaration_digest,
            "native.html.v1",
        ) != payload.digest
    {
        return Err(Failure::SourceIntegrity);
    }
    // Metadata bounds were checked BEFORE hydration. Reserve all retained DTO
    // string representations before any additional clones/construction.
    // The new raw string clones and their retained UTF8 representations are
    // covered conservatively by two full DTO representations. V1 clones none.
    let mixed_binding = if mixed {
        let retained = payload.package.len()
            + payload.version.len()
            + payload.digest.len()
            + payload.artifact_id.len()
            + payload.consented_source_revision.len()
            + payload.declaration_digest.len()
            + latest.len()
            + pointer.len()
            + revision.len()
            + 2 * bundle.len();
        snapshot.budget.charge((2 * retained) as i64, true)?;
        Some(MixedSourceBinding {
            pin: MixedPin {
                package: payload.package.clone(),
                version: payload.version.clone(),
                digest: payload.digest.clone(),
                artifact_id: payload.artifact_id.clone(),
                source_revision: payload.consented_source_revision.clone(),
                declaration_digest: payload.declaration_digest.clone(),
            },
            install_event_id: latest.clone(),
            body_admission_event_id: pointer.clone(),
            source: MixedSource {
                event_id: revision.clone(),
                bundle_sha256: bundle.clone(),
                body_digest: bundle.clone(),
            },
        })
    } else {
        None
    };
    Ok(CurrentAlphaProof {
        body,
        bundle: bundle.clone(),
        mixed_binding,
        binding: ResolvedSource {
            source: tuple("source", &[&viewer, package, &artifact])?,
            generation: tuple("generation", &[&pointer, &latest, handle])?,
            runtime: tuple(
                "runtime-pin",
                &[&revision, "native.html.v1", &bundle, &payload.digest],
            )?,
            declaration: payload.declaration_digest,
            record_type: None,
        },
    })
}

#[cfg(test)]
mod tests;
