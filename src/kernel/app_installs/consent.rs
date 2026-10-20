//! Personal install transitions over the host-verified frozen source set.
use super::*;

mod actions;
mod hosted;
pub(crate) use actions::ACTIONS_DDL;
pub(super) use actions::{
    ensure_schema as ensure_actions_schema, project_recorded as project_action_recorded,
    project_started as project_action_started, ACTION_RECORDED, ACTION_STARTED,
};
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use actions::{finish_app_action_in, start_app_action_in};
#[cfg(feature = "v2-kernel-probe")]
pub(crate) use hosted::{
    admit_app_on, adopt_as, bundle_source_on, launch_source_on, prepare_source_as, preview_as,
    AdoptRequest, AppSourceAdmission,
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

struct Source {
    pin: Value,
    body: String,
    event_seq: i64,
}

async fn source_on(conn: &mut SqliteConnection, request: &InstallRequest) -> Result<Source> {
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&request.declaration)?;
    let row:Option<(String,String,i64)>=sqlx::query_as("SELECT pin_json,source_body,event_seq FROM kernel_app_package_sources WHERE package=? AND version=? AND digest=? AND artifact_id=? AND source_revision=? AND declaration_digest=?")
        .bind(&request.package).bind(&request.version).bind(&request.digest).bind(&request.artifact_id)
        .bind(&request.source_revision).bind(&declaration_digest).fetch_optional(conn).await?;
    let Some((raw, body, event_seq)) = row else {
        return Err(Error::engine("manage_alpha_tabs: unsupported_on_v2"));
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

/// Staging creates caller-asserted consent only. It cannot authorize execution.
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
    mut request: InstallRequest,
) -> Result<ManagementOutcome> {
    normalize(&mut request)?;
    let key = request
        .idempotency_key
        .take()
        .filter(|k| !k.trim().is_empty())
        .unwrap_or_else(|| {
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
        });
    let request_json = serde_json::to_string(&request)?;
    let mut tx = begin_write(db.write_pool()).await?;
    require_member(&mut tx, principal, i64::MAX).await?;
    let record = read_record_on(&mut tx, principal, &request.artifact_id)
        .await?
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    if !is_artifact_on(&mut tx, &record).await? {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let source = source_on(&mut tx, &request).await?;
    let prior:Option<(String,String,String)>=sqlx::query_as("SELECT operation,request_json,event_id FROM kernel_app_install_outcomes WHERE principal=? AND operation_key=?")
        .bind(principal).bind(&key).fetch_optional(&mut *tx).await?;
    if let Some((operation, previous, generation)) = prior {
        if operation != "install" || previous != request_json {
            return Err(Error::conflict(
                "idempotency_key reused for different app intent",
            ));
        }
        let current:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal=? AND package=? AND generation=? AND status='installed')")
            .bind(principal).bind(&request.package).bind(&generation).fetch_one(&mut *tx).await?;
        if !current {
            return Err(Error::conflict("native app installation changed"));
        }
        return management::outcome_on(&mut tx, principal, &request.package, generation, false)
            .await;
    }
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
                format: 1,
                key,
                request,
                source_event_seq: source.event_seq,
                revocation_seq,
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
    if p.format != 1
        || p.key.trim().is_empty()
        || p.request != normalized
        || p.request.idempotency_key.is_some()
        || event.record_id != aggregate(actor, &p.request.package)
    {
        return Err(invalid("invalid install outcome"));
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
    match predecessor {
        Some((generation, status))
            if status == "removed"
                && p.request.expected_install_event_id.as_deref() == Some(generation.as_str()) => {}
        None if p.request.expected_install_event_id.is_none() => (),
        _ => {
            return Err(Error::conflict(
                "native app installation predecessor changed",
            ))
        }
    }
    project_outcome(
        conn,
        event,
        &p.key,
        "install",
        &serde_json::to_string(&p.request)?,
    )
    .await?;
    let row = json!({
        "account_id":account,"package":p.request.package,"version":p.request.version,"digest":p.request.digest,
        "artifact_id":p.request.artifact_id,"consented_source_revision":p.request.source_revision,
        "declaration_digest":source.pin["declaration_digest"],"consented_declaration":source.pin["consented_declaration"],
        "adoption":"caller_asserted","adoption_provenance":null,"status":"installed","event_id":event.id,
        "created_at":event.created_at,"updated_at":event.created_at,"request":p.request.request,
        "consent_revocation_seq":p.revocation_seq,
    });
    sqlx::query("INSERT INTO kernel_app_installs(principal,package,row_json,source_body,generation,status,executable,refusal,previous_generation,event_seq) VALUES(?,?,?,?,?,'installed',0,'adoption_required',?,?) ON CONFLICT(principal,package) DO UPDATE SET row_json=excluded.row_json,source_body=excluded.source_body,generation=excluded.generation,status=excluded.status,executable=0,refusal=excluded.refusal,previous_generation=excluded.previous_generation,event_seq=excluded.event_seq")
        .bind(actor).bind(&p.request.package).bind(row.to_string()).bind(source.body).bind(&event.id)
        .bind(&p.request.expected_install_event_id).bind(event.local_seq).execute(conn).await?;
    Ok(())
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
