//! Hosted sample review and single-use consent over an immutable frozen pin.
use super::*;
use crate::mcp::registry::Caller;
use crate::mcp::tools::alpha_tabs::{AlphaTabAdoptConfirm, AlphaTabPreviewReceipt};

pub(in crate::kernel::app_installs) const ADOPTED: &str = "kernel.app_install_adopted.v1";

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AdoptRequest {
    pub pin: InstallRequest,
    pub receipt_id: String,
    pub nonce: String,
    pub preview_session: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Adopted {
    format: u32,
    key: String,
    request: AdoptRequest,
    source_event_seq: i64,
    revocation_seq: i64,
}

pub(crate) struct PreviewOutcome {
    pub body: String,
    pub body_limit: usize,
    pub pin: Value,
    pub receipt: AlphaTabPreviewReceipt,
}

pub(crate) struct PreparedSource {
    pub body: String,
    pub body_limit: usize,
    pub pin: Value,
    pub current_install: Option<(String, String)>,
}

/// Preparation reads a frozen source under current View; it grants no consent.
pub(crate) async fn prepare_source_as(
    db: &Db,
    principal: &str,
    request: &InstallRequest,
) -> Result<PreparedSource> {
    let mut tx = db.write_pool().begin().await?;
    let account = require_member(&mut tx, principal, i64::MAX).await?;
    let source = source_for_member(&mut tx, principal, &account, request).await?;
    let body_limit = body_limit_on(&mut tx, &request.artifact_id).await?;
    let current_install = sqlx::query_as(
        "SELECT generation,status FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(principal)
    .bind(&request.package)
    .fetch_optional(&mut *tx)
    .await?;
    tx.rollback().await?;
    Ok(PreparedSource {
        body: source.body,
        body_limit,
        pin: source.pin,
        current_install,
    })
}

struct HostedScope {
    account: String,
    database: String,
    session: String,
}

fn hosted_scope(caller: &Caller, pin: &InstallRequest, adopting: bool) -> Result<HostedScope> {
    if caller.host_asserted_app().is_some() {
        return Err(Error::engine(
            "manage_alpha_tabs: app callers cannot consent",
        ));
    }
    let authority = if adopting {
        caller.verified_alpha_tab_adopt()
    } else {
        caller.verified_alpha_tab_preview()
    }
    .ok_or_else(|| {
        Error::engine("manage_alpha_tabs: hosted cookie-session consent authority required")
    })?;
    let account = caller.credential();
    let declaration_digest =
        crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&pin.declaration)?;
    if authority.account_id != account
        || authority.package != pin.package
        || authority.version != pin.version
        || authority.digest != pin.digest
        || authority.artifact_id != pin.artifact_id
        || authority.source_revision != pin.source_revision
        || authority.declaration_digest != declaration_digest
        || !authority.needs.is_empty()
        || !authority.effects.is_empty()
    {
        return Err(Error::engine(
            "manage_alpha_tabs: consent authority pin mismatch",
        ));
    }
    let database = caller
        .hosting_database()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("manage_alpha_tabs: hosted database required"))?;
    let session = caller
        .hosting_session_id()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("manage_alpha_tabs: hosted cookie session required"))?;
    caller
        .hosting_principal()
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::engine("manage_alpha_tabs: hosted account required"))?;
    Ok(HostedScope {
        account: account.into(),
        database: database.into(),
        session: session.into(),
    })
}

async fn require_hosted_account_on(
    conn: &mut SqliteConnection,
    principal: &str,
    caller: &Caller,
) -> Result<()> {
    let catalog = caller
        .hosting_principal()
        .ok_or_else(|| Error::engine("manage_alpha_tabs: hosted account required"))?;
    if !hosted_identity::catalog_account_matches_on(conn, catalog, caller.credential(), principal)
        .await?
    {
        return Err(Error::engine(
            "manage_alpha_tabs: hosted account mapping changed",
        ));
    }
    Ok(())
}

async fn source_for_member(
    conn: &mut SqliteConnection,
    principal: &str,
    account: &str,
    pin: &InstallRequest,
) -> Result<Source> {
    if require_member(conn, principal, i64::MAX).await? != account {
        return Err(Error::engine(
            "manage_alpha_tabs: authenticated account mismatch",
        ));
    }
    let record = read_record_on(conn, principal, &pin.artifact_id)
        .await?
        .ok_or_else(|| Error::engine(HIDDEN_OR_MISSING))?;
    if !is_artifact_on(conn, &record).await? {
        return Err(Error::engine(HIDDEN_OR_MISSING));
    }
    let runtime: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key='runtime'")
            .bind(&pin.artifact_id)
            .fetch_optional(&mut *conn)
            .await?
            .flatten();
    if runtime.as_deref() != Some("native.html.v1") {
        return Err(Error::engine(
            "manage_alpha_tabs: source is not renderable native HTML",
        ));
    }
    source_on(conn, pin).await
}

async fn body_limit_on(conn: &mut SqliteConnection, artifact: &str) -> Result<usize> {
    let marker: Option<String> =
        sqlx::query_scalar("SELECT value FROM kernel_facets WHERE record_id=? AND key=?")
            .bind(artifact)
            .bind(crate::artifact_html::PACKAGE_FACET_KEY)
            .fetch_optional(conn)
            .await?
            .flatten();
    Ok(crate::artifact_html::body_limit_for_package_marker(
        marker.as_deref(),
    ))
}

async fn current_install(
    conn: &mut SqliteConnection,
    principal: &str,
    pin: &InstallRequest,
    before: i64,
) -> Result<(String, Value)> {
    let row: Option<(String, String, String, i64)> = sqlx::query_as(
        "SELECT generation,status,row_json,event_seq FROM kernel_app_installs WHERE principal=? AND package=?",
    ).bind(principal).bind(&pin.package).fetch_optional(conn).await?;
    let Some((generation, status, raw, seq)) = row else {
        return Err(Error::engine("manage_alpha_tabs: installation required"));
    };
    let row: Value = serde_json::from_str(&raw)?;
    let declaration: Value = serde_json::from_str(string(&row, "consented_declaration")?)?;
    if status != "installed"
        || seq >= before
        || row["artifact_id"] != pin.artifact_id
        || row["version"] != pin.version
        || row["digest"] != pin.digest
        || row["consented_source_revision"] != pin.source_revision
        || declaration != pin.declaration
    {
        return Err(Error::conflict("native app installation pin changed"));
    }
    Ok((generation, row))
}

async fn preview_binding(
    conn: &mut SqliteConnection,
    principal: &str,
    scope: HostedScope,
    generation: String,
) -> Result<preview::Binding> {
    let activation_event: String =
        sqlx::query_scalar("SELECT id FROM main.content_events WHERE type=? ORDER BY seq LIMIT 1")
            .bind(ACTIVATED)
            .fetch_one(&mut *conn)
            .await?;
    Ok(preview::Binding {
        database: scope.database,
        hosting_session: scope.session,
        activation_event,
        install_generation: generation,
        revocation_seq: revocation_on(conn, principal, i64::MAX).await?,
    })
}

pub(crate) async fn preview_as(
    db: &Db,
    principal: &str,
    caller: &Caller,
    mut pin: InstallRequest,
) -> Result<PreviewOutcome> {
    normalize(&mut pin)?;
    let scope = hosted_scope(caller, &pin, false)?;
    let mut tx = db.write_pool().begin().await?;
    require_hosted_account_on(&mut tx, principal, caller).await?;
    let source = source_for_member(&mut tx, principal, &scope.account, &pin).await?;
    let (generation, _) = current_install(&mut tx, principal, &pin, i64::MAX).await?;
    let account = scope.account.clone();
    let binding = preview_binding(&mut tx, principal, scope, generation).await?;
    let body_limit = body_limit_on(&mut tx, &pin.artifact_id).await?;
    let manifest = crate::artifact_html::validate_cached_with_limit(&source.body, body_limit)
        .map_err(|error| {
            Error::engine(format!(
                "manage_alpha_tabs: preview refused [{}]",
                error.code
            ))
        })?;
    manifest.require_available_kit().map_err(|error| {
        Error::engine(format!(
            "manage_alpha_tabs: preview refused [{}]",
            error.code
        ))
    })?;
    let receipt = preview::issue(
        &account,
        &source.pin,
        binding,
        chrono::Utc::now().timestamp(),
    )?;
    tx.rollback().await?;
    Ok(PreviewOutcome {
        body: source.body,
        body_limit,
        pin: source.pin,
        receipt,
    })
}

pub(crate) async fn adopt_as(
    db: &Db,
    principal: &str,
    caller: &Caller,
    mut request: AdoptRequest,
) -> Result<ManagementOutcome> {
    normalize(&mut request.pin)?;
    let scope = hosted_scope(caller, &request.pin, true)?;
    let expected = request
        .pin
        .expected_install_event_id
        .clone()
        .ok_or_else(|| Error::engine("manage_alpha_tabs: expected_install_event_id required"))?;
    let key = request
        .pin
        .idempotency_key
        .take()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            format!(
                "alpha-tab-adopted:{principal}:{}:{expected}",
                request.pin.package
            )
        });
    let request_json = serde_json::to_string(&request)?;
    let mut tx = begin_write(db.write_pool()).await?;
    require_hosted_account_on(&mut tx, principal, caller).await?;
    let source = source_for_member(&mut tx, principal, &scope.account, &request.pin).await?;
    let (generation, _) = current_install(&mut tx, principal, &request.pin, i64::MAX).await?;
    let revocation_seq = revocation_on(&mut tx, principal, i64::MAX).await?;
    let prior: Option<(String, String, String)> = sqlx::query_as(
        "SELECT operation,request_json,event_id FROM kernel_app_install_outcomes WHERE principal=? AND operation_key=?",
    ).bind(principal).bind(&key).fetch_optional(&mut *tx).await?;
    if let Some((operation, old, event)) = prior {
        if operation != "adopt" || old != request_json {
            return Err(Error::conflict(
                "idempotency_key reused for different app intent",
            ));
        }
        let current: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_app_installs WHERE principal=? AND package=? AND generation=? AND status='installed' AND executable=1 AND json_extract(row_json,'$.consent_revocation_seq')=?)",
        ).bind(principal).bind(&request.pin.package).bind(&event).bind(revocation_seq)
            .fetch_one(&mut *tx).await?;
        if !current || generation != event {
            return Err(Error::conflict("native app installation changed"));
        }
        return management::outcome_on(&mut tx, principal, &request.pin.package, event, false)
            .await;
    }
    if generation != expected {
        return Err(Error::conflict(
            "native app installation predecessor changed",
        ));
    }
    let account = scope.account.clone();
    let binding = preview_binding(&mut tx, principal, scope, generation.clone()).await?;
    let confirm = AlphaTabAdoptConfirm {
        receipt_id: request.receipt_id.clone(),
        nonce: request.nonce.clone(),
        account_id: account,
        package: request.pin.package.clone(),
        version: request.pin.version.clone(),
        digest: request.pin.digest.clone(),
        artifact_id: request.pin.artifact_id.clone(),
        source_revision: request.pin.source_revision.clone(),
        declaration_digest: string(&source.pin, "declaration_digest")?.into(),
        needs: vec![],
        effects: vec![],
        preview_session: request.preview_session.clone(),
        reason: request.pin.reason.clone(),
        expected_install_event_id: expected,
        current_event_id: generation,
    };
    // All authority/CAS checks precede spending. An uncertain commit leaves the
    // receipt spent; an accepted keyed retry reads its durable outcome instead.
    preview::consume(&confirm, &binding, chrono::Utc::now().timestamp())?;
    let package = request.pin.package.clone();
    let outcome = append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: aggregate(principal, &request.pin.package),
            event_type: ADOPTED.into(),
            actor: Some(principal.into()),
            payload: serde_json::to_value(Adopted {
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

/// Current, snapshot-local facts. The native write lane obtains these again
/// inside its mutation transaction; callers must not cache them as authority.
pub(crate) struct AppSourceAdmission {
    pub principal: String,
    pub account: String,
    pub package: String,
    pub version: String,
    pub generation: String,
    pub install_event_seq: i64,
    pub revocation_epoch: i64,
    pub frozen_source_seq: i64,
    pub pin: Value,
    pub body: String,
    pub body_limit: usize,
}

struct CurrentSource {
    account: String,
    generation: String,
    install_event_seq: i64,
    executable: bool,
    refusal: Option<String>,
    row: Value,
    request: InstallRequest,
    source: Source,
    epoch: i64,
    body_limit: usize,
}

impl CurrentSource {
    fn require_executable(&self) -> Result<()> {
        if !self.executable
            || self.refusal.is_some()
            || self.row["adoption"] != "shell_adopt.v1"
            || self.row["consent_revocation_seq"].as_i64().unwrap_or(0) != self.epoch
        {
            return Err(Error::engine("native app consent is not executable"));
        }
        Ok(())
    }
}

async fn current_source_on(
    conn: &mut SqliteConnection,
    principal: &str,
    package: &str,
    expected_generation: &str,
    expected_digest: Option<&str>,
) -> Result<CurrentSource> {
    require_activated_on(conn).await?;
    let account = require_member(conn, principal, i64::MAX).await?;
    let stored: Option<(String, String, String, bool, Option<String>, i64)> = sqlx::query_as(
        "SELECT row_json,generation,status,executable,refusal,event_seq FROM kernel_app_installs WHERE principal=? AND package=?",
    ).bind(principal).bind(package).fetch_optional(&mut *conn).await?;
    let Some((raw, generation, status, executable, refusal, install_event_seq)) = stored else {
        return Err(Error::engine("native app installation not found"));
    };
    if status != "installed" || generation != expected_generation {
        return Err(Error::engine("native app installation changed"));
    }
    let row: Value = serde_json::from_str(&raw)?;
    if expected_digest.is_some_and(|digest| row["digest"] != digest) {
        return Err(Error::engine("native app source digest changed"));
    }
    let request = InstallRequest {
        package: package.into(),
        version: string(&row, "version")?.into(),
        digest: string(&row, "digest")?.into(),
        artifact_id: string(&row, "artifact_id")?.into(),
        source_revision: string(&row, "consented_source_revision")?.into(),
        declaration: serde_json::from_str(string(&row, "consented_declaration")?)?,
        reason: "Read the exact frozen app source".into(),
        request: None,
        idempotency_key: None,
        expected_install_event_id: Some(generation.clone()),
    };
    let source = source_for_member(conn, principal, &account, &request).await?;
    let epoch = revocation_on(conn, principal, i64::MAX).await?;
    let body_limit = body_limit_on(conn, &request.artifact_id).await?;
    let manifest = crate::artifact_html::validate_cached_with_limit(&source.body, body_limit)
        .map_err(|error| Error::engine(format!("native app source refused [{}]", error.code)))?;
    manifest
        .require_available_kit()
        .map_err(|error| Error::engine(format!("native app source refused [{}]", error.code)))?;
    Ok(CurrentSource {
        account,
        generation,
        install_event_seq,
        executable,
        refusal,
        row,
        request,
        source,
        epoch,
        body_limit,
    })
}

/// A host assertion is only an identity claim. Membership, consent, revocation,
/// the exact source pin and current source View/liveness are proved here.
pub(crate) async fn admit_app_on(
    conn: &mut SqliteConnection,
    principal: &str,
    claim: &crate::mcp::app_attribution::AppAttribution,
) -> Result<AppSourceAdmission> {
    let current = current_source_on(
        conn,
        principal,
        &claim.package,
        &claim.install_event_id,
        None,
    )
    .await?;
    if current.request.version != claim.version {
        return Err(Error::engine("native app installation version changed"));
    }
    current.require_executable()?;
    Ok(AppSourceAdmission {
        principal: principal.into(),
        account: current.account,
        package: current.request.package,
        version: current.request.version,
        generation: current.generation,
        install_event_seq: current.install_event_seq,
        revocation_epoch: current.epoch,
        frozen_source_seq: current.source.event_seq,
        pin: current.source.pin,
        body: current.source.body,
        body_limit: current.body_limit,
    })
}

/// Launch uses the same current consent/source evaluator as app calls and
/// bundle GETs, with H2's verified cookie and H3's catalogue mapping.
pub(crate) async fn launch_source_on(
    conn: &mut SqliteConnection,
    principal: &str,
    caller: &Caller,
    package: &str,
    expected_generation: &str,
) -> Result<AppSourceAdmission> {
    if caller.host_asserted_app().is_some()
        || caller.hosting_database().is_none_or(str::is_empty)
        || caller.hosting_session_id().is_none_or(str::is_empty)
    {
        return Err(Error::engine(
            "native app launch requires a hosted cookie session",
        ));
    }
    require_hosted_account_on(conn, principal, caller).await?;
    let current = current_source_on(conn, principal, package, expected_generation, None).await?;
    current.require_executable()?;
    Ok(AppSourceAdmission {
        principal: principal.into(),
        account: current.account,
        package: current.request.package,
        version: current.request.version,
        generation: current.generation,
        install_event_seq: current.install_event_seq,
        revocation_epoch: current.epoch,
        frozen_source_seq: current.source.event_seq,
        pin: current.source.pin,
        body: current.source.body,
        body_limit: current.body_limit,
    })
}

/// Read-only delivery admission. The transport must first verify the signed
/// URL and freshly admit its exact issuing catalogue session.
pub(crate) async fn bundle_source_on(
    conn: &mut SqliteConnection,
    caller: &Caller,
    package: &str,
    expected_generation: &str,
    digest: &str,
    preview_receipt: Option<&str>,
) -> Result<(String, usize)> {
    let database = caller
        .hosting_database()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("hosted database required"))?;
    let session = caller
        .hosting_session_id()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine("hosted session required"))?;
    let principal: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or_else(|| Error::engine("database membership not found"))?;
    let current =
        current_source_on(conn, &principal, package, expected_generation, Some(digest)).await?;
    require_hosted_account_on(conn, &principal, caller).await?;
    if let Some(receipt_id) = preview_receipt {
        let scope = HostedScope {
            account: current.account.clone(),
            database: database.into(),
            session: session.into(),
        };
        let binding = preview_binding(conn, &principal, scope, current.generation.clone()).await?;
        let receipt = preview::pending(receipt_id, &binding, chrono::Utc::now().timestamp())?;
        if receipt.account_id != current.account
            || receipt.package != package
            || receipt.version != current.request.version
            || receipt.digest != current.request.digest
            || receipt.artifact_id != current.request.artifact_id
            || receipt.source_revision != current.request.source_revision
            || current.source.pin["declaration_digest"] != receipt.declaration_digest
        {
            return Err(Error::engine("native app preview pin changed"));
        }
    } else {
        current.require_executable()?;
    }
    Ok((current.source.body, current.body_limit))
}

pub(in crate::kernel::app_installs) async fn project_adopted(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: Adopted = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("adopt actor missing"))?;
    require_member(conn, actor, event.local_seq).await?;
    let mut normalized = p.request.pin.clone();
    normalize(&mut normalized)?;
    if p.format != 1
        || p.key.trim().is_empty()
        || p.request.pin != normalized
        || p.request.pin.idempotency_key.is_some()
        || event.record_id != aggregate(actor, &p.request.pin.package)
        || p.request.receipt_id.is_empty()
        || p.request.nonce.is_empty()
        || p.request.preview_session.is_empty()
    {
        return Err(invalid("invalid adopted outcome"));
    }
    let source = source_on(conn, &p.request.pin).await?;
    let (generation, mut row) =
        current_install(conn, actor, &p.request.pin, event.local_seq).await?;
    if p.request.pin.expected_install_event_id.as_deref() != Some(generation.as_str())
        || source.event_seq != p.source_event_seq
        || source.event_seq >= event.local_seq
        || revocation_on(conn, actor, event.local_seq).await? != p.revocation_seq
    {
        return Err(invalid(
            "adopt source, predecessor or revocation witness changed",
        ));
    }
    project_outcome(
        conn,
        event,
        &p.key,
        "adopt",
        &serde_json::to_string(&p.request)?,
    )
    .await?;
    row["adoption"] = json!("shell_adopt.v1");
    row["adoption_provenance"] =
        json!({"receipt_id":p.request.receipt_id,"preview_session":p.request.preview_session});
    row["event_id"] = json!(event.id);
    row["updated_at"] = json!(event.created_at);
    row["consent_revocation_seq"] = json!(p.revocation_seq);
    sqlx::query("UPDATE kernel_app_installs SET row_json=?,generation=?,previous_generation=?,event_seq=?,executable=1,refusal=NULL WHERE principal=? AND package=?")
        .bind(row.to_string()).bind(&event.id).bind(generation).bind(event.local_seq)
        .bind(actor).bind(&p.request.pin.package).execute(conn).await?;
    Ok(())
}

pub(in crate::kernel::app_installs) async fn recover_adopted_outcome(
    conn: &mut SqliteConnection,
    event: &EventRow,
) -> Result<()> {
    let p: Adopted = event_payload(event)?;
    project_outcome(
        conn,
        event,
        &p.key,
        "adopt",
        &serde_json::to_string(&p.request)?,
    )
    .await
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod frozen_declaration_tests {
    use super::*;
    use crate::mcp::registry::VerifiedAlphaTabPreview;

    #[test]
    fn snapshot_frozen_declarations_pass_hosted_preview_and_adopt_scope() {
        // Exact declaration shape and canonical digest observed on all four
        // frozen source pins in the archived HQ snapshot. No source bodies,
        // account identities or installation evidence are copied here.
        const DECLARATION: &str = r#"{"contract":"native.app.v2","needs":[],"effects":[]}"#;
        const DIGEST: &str = "c88880b7ec70e0f66547d982b4ed627cd145e9646c61b6708a0cfe07e7a1bcaf";
        for (package, version) in [
            ("agent.docs", "0.8.2"),
            ("agent.docs", "0.9.0"),
            ("agent.spaces", "0.7.0"),
            ("agent.whiteboard", "0.2.0"),
        ] {
            let declaration: Value = serde_json::from_str(DECLARATION).unwrap();
            crate::alpha_tab_sessions::validate_declaration_contract(&declaration).unwrap();
            assert_eq!(declaration["needs"], json!([]));
            assert_eq!(declaration["effects"], json!([]));
            assert_eq!(
                crate::mcp::tools::alpha_tabs::alpha_tab_declaration_digest(&declaration).unwrap(),
                DIGEST
            );
            let pin = InstallRequest {
                package: package.into(),
                version: version.into(),
                digest: format!("sha256:{}", "a".repeat(64)),
                artifact_id: "fixture-source".into(),
                source_revision: "fixture-revision".into(),
                declaration,
                reason: "Review frozen pin".into(),
                request: None,
                idempotency_key: None,
                expected_install_event_id: None,
            };
            for adopting in [false, true] {
                let caller = Caller::authenticated("fixture-account")
                    .with_hosting_context("fixture-account", "fixture-database");
                // SAFETY: test-only stand-in for verified same-origin cookie ingress.
                let caller = unsafe { caller.with_verified_hosting_session("fixture-session") };
                let authority = VerifiedAlphaTabPreview::for_pin(
                    "fixture-account",
                    package,
                    version,
                    &pin.digest,
                    &pin.artifact_id,
                    &pin.source_revision,
                    DIGEST,
                    vec![],
                    vec![],
                );
                let caller = if adopting {
                    caller.with_verified_alpha_tab_adopt(authority)
                } else {
                    caller.with_verified_alpha_tab_preview(authority)
                };
                let scope = hosted_scope(&caller, &pin, adopting).unwrap();
                assert_eq!(scope.account, "fixture-account");
                assert_eq!(scope.database, "fixture-database");
            }
        }
    }
}
