//! Personal install transitions over the host-verified frozen source set.
use super::*;

mod actions;
mod hosted;
pub(crate) use actions::ACTIONS_DDL;
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use actions::{
    bind_update_action_on, finish_app_action_in, start_app_action_in, start_declared_app_action_in,
    RoutedActionBinding,
};
pub(super) use actions::{
    ensure_schema as ensure_actions_schema, project_recorded as project_action_recorded,
    project_started as project_action_started, ACTION_RECORDED, ACTION_STARTED,
};
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use hosted::{
    admit_app_on, admit_install_on, adopt_as, bundle_source_on, launch_source_on,
    prepare_source_as, preview_as, AdoptRequest, AppSourceAdmission,
};
pub(super) use hosted::{project_adopted, recover_adopted_outcome, ADOPTED};

pub(super) const RECORDED: &str = "kernel.app_install_recorded.v1";
pub(crate) const OUTCOMES_DDL: &str = "CREATE TABLE kernel_app_install_outcomes (
 principal TEXT NOT NULL, operation_key TEXT NOT NULL, operation TEXT NOT NULL,
 request_json TEXT NOT NULL CHECK(json_valid(request_json)), event_id TEXT NOT NULL,
 event_seq INTEGER NOT NULL, PRIMARY KEY(principal,operation_key))";

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    pub package: String,
    pub version: String,
    pub digest: String,
    pub artifact_id: String,
    pub source_revision: String,
    pub declaration: Value,
    pub reason: String,
    #[serde(default)]
    pub request: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub expected_install_event_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Recorded {
    format: u32,
    key: String,
    request: InstallRequest,
    source_event_seq: i64,
    revocation_seq: i64,
    /// The shelf entry this install was enabled from. Set by the engine from
    /// the live shelf, never by a caller; absent for personal installs, which
    /// keeps every earlier event byte-identical.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shelf_event_id: Option<String>,
}

pub struct InstallOutcome {
    pub generation: String,
    pub changed: bool,
}

fn normalize(request: &mut InstallRequest) -> Result<()> {
    if request.reason.trim().is_empty() || request.reason.len() > 1024 {
        return Err(Error::engine(
            "manage_alpha_tabs: reason must be 1..1024 bytes",
        ));
    }
    if request
        .request
        .as_ref()
        .is_some_and(|s| s.trim().is_empty())
    {
        request.request = None;
    }
    if request
        .request
        .as_ref()
        .is_some_and(|s| s.chars().count() > crate::control::ALPHA_TAB_REQUEST_MAX_CHARS)
    {
        return Err(Error::engine("manage_alpha_tabs: request too long"));
    }
    Ok(())
}

pub(super) async fn require_member(
    conn: &mut SqliteConnection,
    principal: &str,
    before: i64,
) -> Result<String> {
    if !hosted_identity::account_admitted_before(conn, principal, before).await? {
        return Err(Error::engine("database membership not found"));
    }
    sqlx::query_scalar(
        "SELECT auth_binding FROM main.kernel_principals WHERE principal_id=? AND kind='account'",
    )
    .bind(principal)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| Error::engine("database membership not found"))
}

pub(super) struct Source {
    pub(super) pin: Value,
    body: String,
    event_seq: i64,
}

pub(super) async fn source_on(
    conn: &mut SqliteConnection,
    request: &InstallRequest,
) -> Result<Source> {
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    let _ = super::SOURCE_ADMISSIONS.try_with(|count| count.set(count.get() + 1));
    if !declarations::source_supported(&request.declaration) {
        return Err(Error::engine(NOT_YET_AVAILABLE));
    }
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&request.declaration)?;
    let row:Option<(String,String,i64)>=sqlx::query_as("SELECT pin_json,source_body,event_seq FROM kernel_app_package_sources WHERE package=? AND version=? AND digest=? AND artifact_id=? AND source_revision=? AND declaration_digest=?")
        .bind(&request.package).bind(&request.version).bind(&request.digest).bind(&request.artifact_id)
        .bind(&request.source_revision).bind(&declaration_digest).fetch_optional(&mut *conn).await?;
    let row = if row.is_some() {
        row
    } else {
        retained_sources_on(conn, Some(&request.artifact_id))
            .await?
            .into_iter()
            .find(|(pin, _, _)| {
                pin["package"] == request.package
                    && pin["version"] == request.version
                    && pin["digest"] == request.digest
                    && pin["source_revision"] == request.source_revision
                    && pin["declaration_digest"] == declaration_digest
            })
            .map(|(pin, body, seq)| (pin.to_string(), body, seq))
    };
    let row = match row {
        Some(row) => Some(row),
        None => sources::native_pin_on(conn, request)
            .await?
            .filter(|(p, _, _)| p["digest"] == request.digest)
            .map(|(p, b, s)| (p.to_string(), b, s)),
    };
    let Some((raw, body, event_seq)) = row else {
        return Err(Error::engine(
            if declarations::declarative(&request.declaration).is_ok() {
                NOT_YET_AVAILABLE
            } else {
                "manage_alpha_tabs: unsupported_on_v2"
            },
        ));
    };
    let pin: Value = serde_json::from_str(&raw)?;
    let declaration: Value = serde_json::from_str(string(&pin, "consented_declaration")?)?;
    let bundle = crate::mcp::tools::alpha_tabs::alpha_tab_bundle_digest(&body);
    if declaration != request.declaration
        || pin["format"] != 1
        || pin["runtime"] != "native.html.v1"
        || pin["bundle_sha256"] != bundle
        || request.digest
            != crate::mcp::tools::alpha_tabs::alpha_tab_digest(
                &bundle,
                &declaration_digest,
                "native.html.v1",
            )
    {
        return Err(invalid("frozen source pin mismatch"));
    }
    Ok(Source {
        pin,
        body,
        event_seq,
    })
}

async fn revocation_on(conn: &mut SqliteConnection, principal: &str, before: i64) -> Result<i64> {
    Ok(sqlx::query_scalar(
        "SELECT event_seq FROM kernel_app_consent_revocations WHERE principal=? AND event_seq<?",
    )
    .bind(principal)
    .bind(before)
    .fetch_optional(conn)
    .await?
    .unwrap_or(0))
}

/// Fresh installs stage caller-asserted consent. Native updates may carry verified
/// adoption when their canonical permission declaration is unchanged.
/// The current source View and account membership gate both retries and effects.
pub async fn install_as(
    db: &Db,
    principal: &str,
    request: InstallRequest,
) -> Result<InstallOutcome> {
    install_for_user_as(db, principal, request)
        .await
        .map(|result| result.outcome)
}

pub(crate) async fn install_for_user_as(
    db: &Db,
    principal: &str,
    request: InstallRequest,
) -> Result<ManagementOutcome> {
    install_inner(db, principal, request, None).await
}

/// Enable a workspace shelf app for the caller, and only for the caller. The
/// pin comes from the live shelf entry named by `shelf_event_id`; the request
/// supplies no pin field. This stages the member's own install row exactly as
/// a personal install does, and consent still needs the one-click preview and
/// adopt. It needs workspace membership and nothing more, so view-only
/// members can enable for themselves.
pub(crate) async fn install_from_shelf_as(
    db: &Db,
    principal: &str,
    package: &str,
    shelf_event_id: &str,
    reason: Option<String>,
    idempotency_key: Option<String>,
) -> Result<ManagementOutcome> {
    let request = InstallRequest {
        package: package.into(),
        version: String::new(),
        digest: String::new(),
        artifact_id: String::new(),
        source_revision: String::new(),
        declaration: Value::Null,
        reason: reason
            .filter(|r| !r.trim().is_empty())
            .unwrap_or_else(|| "Enable this workspace app for myself".into()),
        request: None,
        idempotency_key,
        expected_install_event_id: None,
    };
    install_inner(db, principal, request, Some(shelf_event_id.into())).await
}

async fn row_is_on_pin_on(
    conn: &mut SqliteConnection,
    principal: &str,
    request: &InstallRequest,
) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT json_extract(row_json,'$.artifact_id')=? AND json_extract(row_json,'$.consented_source_revision')=? FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(&request.artifact_id)
    .bind(&request.source_revision)
    .bind(principal)
    .bind(&request.package)
    .fetch_one(conn)
    .await?)
}

fn intent_without_predecessor(request_json: &str) -> Option<String> {
    let mut request: InstallRequest = serde_json::from_str(request_json).ok()?;
    request.expected_install_event_id = None;
    serde_json::to_string(&request).ok()
}

async fn install_inner(
    db: &Db,
    principal: &str,
    mut request: InstallRequest,
    shelf_event: Option<String>,
) -> Result<ManagementOutcome> {
    normalize(&mut request)?;
    let supplied_key = request
        .idempotency_key
        .take()
        .filter(|k| !k.trim().is_empty());
    let mut tx = begin_write(db.write_pool()).await?;
    require_member(&mut tx, principal, i64::MAX).await?;
    if let Some(event_id) = &shelf_event {
        // The pin is read from the live shelf entry, never from the request.
        let entry = match shelf::shelf_before(&mut tx, &request.package, i64::MAX).await? {
            Some(shelf::Shelf::Live(entry)) if entry.shelf_event_id == *event_id => entry,
            Some(shelf::Shelf::Removed { .. }) => return Err(shelf::removed_error()),
            Some(shelf::Shelf::Live(_)) => {
                return Err(Error::conflict(
                    "workspace shelf entry changed; list the shelf and retry",
                ))
            }
            None => return Err(Error::conflict("this app is not on the workspace shelf")),
        };
        let mut pinned = shelf::request_for_on(&mut tx, &entry).await?;
        pinned.reason = std::mem::take(&mut request.reason);
        pinned.request = request.request.take();
        request = pinned;
    } else if sources::is_native_on(&mut tx, &request.artifact_id, &request.source_revision).await?
        && shelf::is_source_on(&mut tx, &request.artifact_id, &request.source_revision).await?
    {
        // A shelf source is consented to only through the shelf, so the
        // install is stamped with the entry it came from and removal applies.
        return Err(Error::engine(
            "manage_alpha_tabs: this app comes from the workspace shelf; enable it from the shelf",
        ));
    }
    let predecessor: Option<(String, String)> = sqlx::query_as(
        "SELECT generation,status FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(principal)
    .bind(&request.package)
    .fetch_optional(&mut *tx)
    .await?;
    let shelf_default_key = match &shelf_event {
        Some(event_id) if supplied_key.is_none() => {
            let base = format!(
                "alpha-tab-install:{principal}:{}:shelf:{event_id}",
                request.package
            );
            Some(match &predecessor {
                // A fresh enable after the member's own removal is a new
                // intent: key it by the removed generation it follows.
                Some((generation, status)) if status == "removed" => {
                    format!("{base}:after:{generation}")
                }
                // Otherwise a retry maps to the latest attempt for this entry
                // (the first enable, or the latest re-enable), which stays
                // stable once that attempt has been adopted.
                _ => sqlx::query_scalar::<_, String>(
                    "SELECT operation_key FROM kernel_app_install_outcomes WHERE principal=? AND (operation_key=? OR substr(operation_key,1,?)=?) ORDER BY event_seq DESC LIMIT 1",
                )
                .bind(principal)
                .bind(&base)
                .bind(base.len() as i64 + 7)
                .bind(format!("{base}:after:"))
                .fetch_optional(&mut *tx)
                .await?
                .unwrap_or(base),
            })
        }
        _ => None,
    };
    let key = supplied_key
        .clone()
        .or(shelf_default_key)
        .unwrap_or_else(|| {
            {
                format!(
                    "alpha-tab-install:{principal}:{}:{}:{}:{}",
                    request.package,
                    request.version,
                    request.digest,
                    request
                        .expected_install_event_id
                        .as_deref()
                        .unwrap_or("genesis")
                )
            }
        });
    let prior_outcome: Option<(String, String, String)> = sqlx::query_as("SELECT operation,request_json,event_id FROM kernel_app_install_outcomes WHERE principal=? AND operation_key=?")
        .bind(principal).bind(&key).fetch_optional(&mut *tx).await?;
    if shelf_event.is_some() && prior_outcome.is_none() {
        // Enabling is a first consent or a fresh one after the member's own
        // removal. It never rewrites a live row, so it cannot disturb another
        // pin or an earlier consent.
        request.expected_install_event_id =
            match predecessor {
                None => None,
                Some((generation, status)) if status == "removed" => Some(generation),
                // The member's own live row is on another pin (an earlier shelf
                // version, or a personal install of this package): this is the
                // update, or the lazy move onto the shared source. It stages the
                // same CAS-guarded transition as any update: the running row is
                // untouched until projection carries it (unchanged declaration)
                // or the member consents to the pending one.
                Some((generation, status))
                    if status == "installed"
                        && !row_is_on_pin_on(&mut tx, principal, &request).await? =>
                {
                    Some(generation)
                }
                // A disabled row exists only from a v1 import (v2 has no disable
                // action). It is never revived silently: remove it, then enable
                // from the shelf, which asks for fresh consent.
                Some((_, status)) if status == "disabled" => return Err(Error::conflict(
                    "this app is turned off for you; remove it, then enable it from the workspace",
                )),
                Some(_) => {
                    return Err(Error::conflict(
                        "you already have this app; open it from your apps to review it",
                    ))
                }
            };
    }
    let request_json = serde_json::to_string(&request)?;
    if shelf_event.is_none() {
        let record = read_record_on(&mut tx, principal, &request.artifact_id)
            .await?
            .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
        if !is_artifact_on(&mut tx, &record).await? {
            return Err(Error::engine(HIDDEN_OR_MISSING));
        }
    }
    let source = source_on(&mut tx, &request).await?;
    if sources::is_native_on(&mut tx, &request.artifact_id, &request.source_revision).await? {
        sources::require_update_owner_on(
            &mut tx,
            principal,
            &request.artifact_id,
            Some(&request.package),
            &request.source_revision,
        )
        .await?;
    }
    if let Some((operation, previous, generation)) = prior_outcome {
        let same = if shelf_event.is_some() {
            intent_without_predecessor(&previous) == intent_without_predecessor(&request_json)
        } else {
            previous == request_json
        };
        if operation != "install" || !same {
            return Err(Error::conflict(
                "idempotency_key reused for different app intent",
            ));
        }
        let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal=? AND package=? AND generation=? AND status='installed')")
            .bind(principal).bind(&request.package).bind(&generation).fetch_one(&mut *tx).await?;
        let mut outcome_generation = generation.clone();
        if !current
            && pending_on(&mut tx, principal, &request.package)
                .await?
                .is_none_or(|(id, _, _)| id != generation)
        {
            // A retry after this attempt was adopted: adoption moves the
            // running generation to the adoption event and records the staged
            // generation as its predecessor. Return that adopted install;
            // any other change (removal, re-pin) still refuses.
            // Only a shelf enable recovers this way; a stale ordinary staging
            // retry after adoption still refuses. The witness is the running
            // generation's retained adoption event, whose pin names this exact
            // staged attempt and matches the retried request.
            // `previous_generation` alone is no witness: carried updates set
            // it too.
            let adopted: Option<String> = sqlx::query_scalar("SELECT i.generation FROM kernel_app_installs i JOIN content_events e ON e.id=i.generation WHERE i.principal=? AND i.package=? AND i.status='installed' AND i.generation<>? AND e.type=? AND e.record_id=? AND json_extract(e.payload,'$.request.pin.expected_install_event_id')=? AND json_extract(e.payload,'$.request.pin.package')=? AND json_extract(e.payload,'$.request.pin.version')=? AND json_extract(e.payload,'$.request.pin.digest')=? AND json_extract(e.payload,'$.request.pin.artifact_id')=? AND json_extract(e.payload,'$.request.pin.source_revision')=?")
                .bind(principal).bind(&request.package).bind(&generation).bind(ADOPTED)
                .bind(aggregate(principal, &request.package)).bind(&generation)
                .bind(&request.package).bind(&request.version).bind(&request.digest)
                .bind(&request.artifact_id).bind(&request.source_revision)
                .fetch_optional(&mut *tx).await?;
            match adopted.filter(|_| shelf_event.is_some()) {
                Some(running) => outcome_generation = running,
                None => return Err(Error::conflict("native app installation changed")),
            }
        }
        return management::outcome_on(
            &mut tx,
            principal,
            &request.package,
            outcome_generation,
            false,
        )
        .await;
    }
    // Formats 1–2 retain their historical staging semantics during replay.
    // Format 3 permits verified unchanged-declaration carry on native updates.
    let format =
        if sources::is_native_on(&mut tx, &request.artifact_id, &request.source_revision).await? {
            3
        } else {
            1
        };
    let revocation_seq = revocation_on(&mut tx, principal, i64::MAX).await?;
    let package = request.package.clone();
    let outcome = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: aggregate(principal, &request.package),
            event_type: RECORDED.into(),
            actor: Some(principal.into()),
            payload: serde_json::to_value(Recorded {
                format,
                key,
                request,
                source_event_seq: source.event_seq,
                revocation_seq,
                shelf_event_id: shelf_event,
            })?,
        },
        &mut crate::act::ActAllocation::new(),
    )
    .await?;
    let result = management::outcome_on(&mut tx, principal, &package, outcome.id, true).await?;
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

pub(super) async fn project_recorded(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Recorded = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("install actor missing"))?;
    let account = require_member(conn, actor, event.local_seq).await?;
    let mut normalized = p.request.clone();
    normalize(&mut normalized)?;
    if !matches!(p.format, 1..=3)
        || p.key.trim().is_empty()
        || p.request != normalized
        || p.request.idempotency_key.is_some()
        || event.record_id != aggregate(actor, &p.request.package)
    {
        return Err(invalid("invalid install outcome"));
    }
    // Shelf provenance is engine-stamped: a shelf source is installed only
    // with the live shelf entry it came from, and nothing else carries one.
    let from_shelf =
        shelf::is_source_on(conn, &p.request.artifact_id, &p.request.source_revision).await?;
    match (&p.shelf_event_id, from_shelf) {
        (Some(id), true) => {
            let entry = shelf::require_live_pin_before_on(
                conn,
                &p.request.package,
                &p.request.artifact_id,
                &p.request.source_revision,
                event.local_seq,
            )
            .await?;
            if entry.shelf_event_id != *id || p.format < 3 {
                return Err(invalid("install shelf entry mismatch"));
            }
        }
        (None, false) => {}
        _ => return Err(invalid("install shelf provenance mismatch")),
    }
    let source = source_on(conn, &p.request).await?;
    if source.event_seq != p.source_event_seq
        || source.event_seq >= event.local_seq
        || revocation_on(conn, actor, event.local_seq).await? != p.revocation_seq
    {
        return Err(invalid("install source or revocation witness changed"));
    }
    let predecessor: Option<(String, String)> = sqlx::query_as(
        "SELECT generation,status FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(actor)
    .bind(&p.request.package)
    .fetch_optional(&mut *conn)
    .await?;
    // The folder grant is per (principal, package), not per generation:
    // carry it across this full row rewrite (absent stays absent, so
    // pre-scope rows keep their exact bytes).
    let prior_scope: Option<String> = sqlx::query_scalar(
        "SELECT json_extract(row_json,'$.scope') FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(actor)
    .bind(&p.request.package)
    .fetch_optional(&mut *conn)
    .await?
    .flatten();
    let updating = predecessor
        .as_ref()
        .is_some_and(|(_, status)| status == "installed");
    match predecessor {
        Some((generation, status))
            if (status == "removed" || (p.format >= 2 && status == "installed"))
                && p.request.expected_install_event_id.as_deref() == Some(generation.as_str()) => {}
        None if p.request.expected_install_event_id.is_none() => (),
        _ => {
            return Err(Error::conflict(
                "native app installation predecessor changed",
            ))
        }
    }
    if sources::is_native_on(conn, &p.request.artifact_id, &p.request.source_revision).await? {
        sources::require_update_owner_before_on(
            conn,
            actor,
            &p.request.artifact_id,
            Some(&p.request.package),
            &p.request.source_revision,
            event.local_seq,
        )
        .await?;
    }
    if updating {
        if !sources::is_native_on(conn, &p.request.artifact_id, &p.request.source_revision).await? {
            return Err(invalid("updates require a native attested source revision"));
        }
        let same:bool=sqlx::query_scalar("SELECT json_extract(row_json,'$.consented_source_revision')=? FROM kernel_app_installs WHERE principal=? AND package=?")
            .bind(&p.request.source_revision).bind(actor).bind(&p.request.package).fetch_one(&mut *conn).await?;
        if same {
            return Err(invalid("this source revision is already installed"));
        }
        sources::require_update_owner_before_on(
            conn,
            actor,
            &p.request.artifact_id,
            Some(&p.request.package),
            &p.request.source_revision,
            event.local_seq,
        )
        .await?;
        let current_artifact: String = sqlx::query_scalar("SELECT json_extract(row_json,'$.artifact_id') FROM kernel_app_installs WHERE principal=? AND package=?")
            .bind(actor).bind(&p.request.package).fetch_one(&mut *conn).await?;
        // A shelf pin lives on the shared artifact, so a member's move onto it
        // (a later shelf version, or off a personal artifact) changes the
        // artifact by design. That is safe because the event is stamped with,
        // and projects into, the actor's own aggregate and row only, and it
        // must name the live shelf entry (checked above).
        if current_artifact != p.request.artifact_id && p.shelf_event_id.is_none() {
            if !materialized::is_materialized_on(
                conn,
                &p.request.artifact_id,
                &p.request.source_revision,
            )
            .await?
            {
                return Err(invalid("updates must use the existing package artifact"));
            }
            materialized::require_rebind_before_on(conn, actor, &p.request, event.local_seq)
                .await?;
        }
    }
    // Retain the accepted native pin before a later publication changes the head.
    if p.format >= 2 {
        let row = staged_row(&p, &source, &account, event);
        project_source(
            conn,
            &CapturedInstall {
                principal: actor.into(),
                row,
                body: Some(source.body.clone()),
                refusal: None,
            },
            source.event_seq,
        )
        .await?;
    }
    project_outcome(
        conn,
        event,
        &p.key,
        "install",
        &serde_json::to_string(&p.request)?,
    )
    .await?;
    let mut row = staged_row(&p, &source, &account, event);
    if let Some(prior) = prior_scope {
        row["scope"] = serde_json::from_str(&prior)?;
    }
    let carried = if updating && p.format == 3 {
        carried_adoption_on(conn, actor, &p, &source, &account, &mut row).await?
    } else {
        false
    };
    if updating && !carried {
        return Ok(());
    }
    sqlx::query("INSERT INTO kernel_app_installs(principal,package,row_json,source_body,generation,status,executable,refusal,previous_generation,event_seq) VALUES(?,?,?,?,?,'installed',?,?,?,?) ON CONFLICT(principal,package) DO UPDATE SET row_json=excluded.row_json,source_body=excluded.source_body,generation=excluded.generation,status=excluded.status,executable=excluded.executable,refusal=excluded.refusal,previous_generation=excluded.previous_generation,event_seq=excluded.event_seq")
        .bind(actor).bind(&p.request.package).bind(row.to_string()).bind(source.body).bind(&event.id)
        .bind(carried).bind(if carried { None } else { Some("adoption_required") })
        .bind(&p.request.expected_install_event_id).bind(event.local_seq).execute(conn).await?;
    Ok(())
}

/// Derive carry only from an executable, unrevoked predecessor and its verified
/// source. This runs in the same transaction as the guarded install projection,
/// including replay. Caller arguments never supply adoption or provenance.
async fn carried_adoption_on(
    conn: &mut SqliteConnection,
    actor: &str,
    p: &Recorded,
    source: &Source,
    account: &str,
    row: &mut Value,
) -> Result<bool> {
    let (raw, generation, executable, refusal): (String, String, bool, Option<String>) =
        sqlx::query_as("SELECT row_json,generation,executable,refusal FROM kernel_app_installs WHERE principal=? AND package=?")
            .bind(actor).bind(&p.request.package).fetch_one(&mut *conn).await?;
    let previous: Value = serde_json::from_str(&raw)?;
    if (previous["artifact_id"] != p.request.artifact_id && p.shelf_event_id.is_none())
        || materialized::is_materialized_on(
            conn,
            &p.request.artifact_id,
            &p.request.source_revision,
        )
        .await?
    {
        return Ok(false);
    }
    if !executable
        || refusal.is_some()
        || !previous["adoption"].as_str().is_some_and(verified_adoption)
        || previous["consent_revocation_seq"].as_i64().unwrap_or(0) != p.revocation_seq
        || previous["account_id"] != account
        || previous["declaration_digest"] != source.pin["declaration_digest"]
    {
        return Ok(false);
    }
    let declaration: Value = serde_json::from_str(string(&previous, "consented_declaration")?)?;
    let digest = crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration)?;
    if previous["declaration_digest"] != digest {
        return Ok(false);
    }
    let prior_request = InstallRequest {
        package: p.request.package.clone(),
        version: string(&previous, "version")?.into(),
        digest: string(&previous, "digest")?.into(),
        artifact_id: string(&previous, "artifact_id")?.into(),
        source_revision: string(&previous, "consented_source_revision")?.into(),
        declaration,
        reason: p.request.reason.clone(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: None,
    };
    // A missing or invalid retained source cannot confer carry eligibility.
    match source_on(conn, &prior_request).await {
        Ok(_) => (),
        Err(Error::Sqlx(error)) => return Err(Error::Sqlx(error)),
        Err(_) => return Ok(false),
    }
    let provenance = match &previous["adoption_provenance"] {
        Value::String(raw) => serde_json::from_str::<Value>(raw).ok(),
        Value::Object(_) => Some(previous["adoption_provenance"].clone()),
        _ => None,
    };
    let Some(mut provenance) = provenance.filter(Value::is_object) else {
        // Legacy adopted labels without provenance need a fresh adoption root.
        return Ok(false);
    };
    let kind: Option<String> = sqlx::query_scalar("SELECT type FROM content_events WHERE id=?")
        .bind(&generation)
        .fetch_optional(&mut *conn)
        .await?;
    if kind.as_deref() == Some(ADOPTED) {
        if provenance["receipt_id"].as_str().is_none_or(str::is_empty)
            || provenance["preview_session"]
                .as_str()
                .is_none_or(str::is_empty)
        {
            return Ok(false);
        }
        provenance["original_adoption_event_id"] = json!(generation);
        provenance["original_adoption_method"] = previous["adoption"].clone();
        provenance["adopted_declaration_digest"] = json!(digest);
        provenance["canonicalization_version"] = json!("alpha-tab-declaration.v1");
        provenance["original_source_revision"] = previous["consented_source_revision"].clone();
        provenance["original_bundle_digest"] = previous["digest"].clone();
        provenance["reviewed_source_revision"] = previous["consented_source_revision"].clone();
        provenance["reviewed_bundle_digest"] = previous["digest"].clone();
    } else if provenance["adopted_declaration_digest"] != digest
        || provenance["canonicalization_version"] != "alpha-tab-declaration.v1"
        || provenance["original_adoption_method"] != previous["adoption"]
        || provenance["original_adoption_event_id"]
            .as_str()
            .is_none_or(str::is_empty)
        || provenance["original_source_revision"]
            .as_str()
            .is_none_or(str::is_empty)
        || provenance["original_bundle_digest"]
            .as_str()
            .is_none_or(str::is_empty)
    {
        return Ok(false);
    }
    provenance["carried_from_event_id"] = json!(generation);
    row["adoption"] = previous["adoption"].clone();
    row["adoption_provenance"] = provenance;
    Ok(true)
}

pub(super) async fn recover_outcome(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Recorded = event_payload(event)?;
    project_outcome(
        conn,
        event,
        &p.key,
        "install",
        &serde_json::to_string(&p.request)?,
    )
    .await
}

/// The index is derived from canonical accepted outcomes, including on recovery.
pub(super) async fn project_outcome(
    conn: &mut SqliteConnection,
    event: &EventRow,
    key: &str,
    operation: &str,
    request_json: &str,
) -> Result<()> {
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("install outcome actor missing"))?;
    sqlx::query("INSERT INTO kernel_app_install_outcomes VALUES(?,?,?,?,?,?) ON CONFLICT(principal,operation_key) DO NOTHING")
        .bind(actor).bind(key).bind(operation).bind(request_json).bind(&event.id).bind(event.local_seq).execute(&mut *conn).await?;
    let retained:(String,String,String,i64)=sqlx::query_as("SELECT operation,request_json,event_id,event_seq FROM kernel_app_install_outcomes WHERE principal=? AND operation_key=?")
        .bind(actor).bind(key).fetch_one(conn).await?;
    if retained
        != (
            operation.into(),
            request_json.into(),
            event.id.clone(),
            event.local_seq,
        )
    {
        return Err(Error::conflict(
            "native app operation key has conflicting outcomes",
        ));
    }
    Ok(())
}

fn staged_row(p: &Recorded, source: &Source, account: &str, event: &EventRow) -> Value {
    let mut row = json!({"account_id":account,"package":p.request.package,"version":p.request.version,"digest":p.request.digest,
        "artifact_id":p.request.artifact_id,"consented_source_revision":p.request.source_revision,
        "declaration_digest":source.pin["declaration_digest"],"consented_declaration":source.pin["consented_declaration"],
        "adoption":"caller_asserted","adoption_provenance":null,"status":"installed","event_id":event.id,
        "created_at":event.created_at,"updated_at":event.created_at,"request":p.request.request,"consent_revocation_seq":p.revocation_seq});
    if let Some(shelf_event_id) = &p.shelf_event_id {
        row["shelf_event_id"] = json!(shelf_event_id);
    }
    row
}

/// Pending updates are canonical accepted outcomes, separate from running consent.
/// A removal, adoption or offboarding changes the predecessor and invalidates them.
pub(super) async fn pending_on(
    conn: &mut SqliteConnection,
    actor: &str,
    package: &str,
) -> Result<Option<(String, Value, i64)>> {
    pending_before_on(conn, actor, package, i64::MAX).await
}

pub(super) async fn pending_before_on(
    conn: &mut SqliteConnection,
    actor: &str,
    package: &str,
    before: i64,
) -> Result<Option<(String, Value, i64)>> {
    let event: Option<(String,String,i64,String)> = sqlx::query_as("SELECT e.id,e.payload,e.seq,e.created_at FROM kernel_app_install_outcomes o JOIN content_events e ON e.id=o.event_id JOIN kernel_app_installs i ON i.principal=o.principal AND i.package=json_extract(o.request_json,'$.package') WHERE o.principal=? AND i.package=? AND i.status='installed' AND o.operation='install' AND e.seq<? AND json_extract(e.payload,'$.format') IN (2,3) AND json_extract(o.request_json,'$.expected_install_event_id')=i.generation ORDER BY e.seq DESC LIMIT 1")
        .bind(actor).bind(package).bind(before).fetch_optional(&mut *conn).await?;
    let Some((id, raw, seq, created)) = event else {
        return Ok(None);
    };
    let p: Recorded = serde_json::from_str(&raw)?;
    if revocation_on(conn, actor, before).await? != p.revocation_seq {
        return Ok(None);
    }
    let source = source_on(conn, &p.request).await?;
    let account = require_member(conn, actor, before).await?;
    let mut row = json!({"account_id":account,"package":p.request.package,"version":p.request.version,"digest":p.request.digest,
        "artifact_id":p.request.artifact_id,"consented_source_revision":p.request.source_revision,
        "declaration_digest":source.pin["declaration_digest"],"consented_declaration":source.pin["consented_declaration"],
        "adoption":"caller_asserted","adoption_provenance":null,"status":"installed","event_id":id,
        "created_at":created,"updated_at":created,"request":p.request.request,"consent_revocation_seq":p.revocation_seq});
    if let Some(shelf_event_id) = &p.shelf_event_id {
        row["shelf_event_id"] = json!(shelf_event_id);
    }
    Ok(Some((id, row, seq)))
}

pub(super) async fn recover_source(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: Recorded = event_payload(event)?;
    if p.format < 2 {
        return Ok(());
    }
    let source = source_on(conn, &p.request).await?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("install actor missing"))?;
    let account = require_member(conn, actor, event.local_seq).await?;
    project_source(
        conn,
        &CapturedInstall {
            principal: actor.into(),
            row: staged_row(&p, &source, &account, event),
            body: Some(source.body),
            refusal: None,
        },
        source.event_seq,
    )
    .await
}
