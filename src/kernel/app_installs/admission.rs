//! Live consent checks shared by ordinary app reads, writes and the later
//! AppDataNeeds adapter. The dispatch carries a claim, never a permission.
use super::*;
use crate::mcp::app_attribution::AppAttribution;
use crate::mcp::Caller;

/// Subscription callers are freshly admitted credentials, without the
/// transport-only cookie/catalogue fields. Resolve their account, consent
/// and source together on this evaluation's actual snapshot.
pub(crate) async fn admit_data_as(
    db: &Db,
    caller: &Caller,
    package: &str,
    expected_generation: &str,
) -> Result<AppSourceAdmission> {
    let mut snapshot = db.write_pool().begin().await?;
    let principal: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(caller.credential())
    .fetch_optional(&mut *snapshot)
    .await?
    .ok_or_else(|| Error::engine("database membership not found"))?;
    if consent::require_member(&mut snapshot, &principal, i64::MAX).await? != caller.credential() {
        return Err(Error::engine("native app data principal changed"));
    }
    let version: String = sqlx::query_scalar::<_, Option<String>>(
        "SELECT json_extract(row_json,'$.version') FROM kernel_app_installs WHERE principal=? AND package=?",
    ).bind(&principal).bind(package).fetch_optional(&mut *snapshot).await?.flatten()
        .ok_or_else(|| Error::engine("native app installation not found"))?;
    let claim = AppAttribution::new(package, version, expected_generation)?;
    if caller.host_asserted_app().is_some_and(|app| app != &claim) {
        return Err(Error::engine(
            "native app data request differs from its app identity",
        ));
    }
    let admitted = admit_install_on(
        &mut snapshot,
        &principal,
        &claim.package,
        &claim.install_event_id,
    )
    .await?;
    snapshot.rollback().await?;
    Ok(admitted)
}

/// Resolve the authenticated account and source in one authority snapshot.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn admit_account_app_as(
    db: &Db,
    account: &str,
    claim: &AppAttribution,
) -> Result<AppSourceAdmission> {
    let mut snapshot = db.write_pool().begin().await?;
    let principal: String = sqlx::query_scalar(
        "SELECT principal_id FROM kernel_principals WHERE auth_binding=? AND kind='account'",
    )
    .bind(account)
    .fetch_optional(&mut *snapshot)
    .await?
    .ok_or_else(|| Error::engine("database membership not found"))?;
    let admitted = admit_app_on(&mut snapshot, &principal, claim).await?;
    snapshot.rollback().await?;
    Ok(admitted)
}

/// Each bounded read/mutation calls this on its own actual connection.
/// Reusing the existing provenance scope also preserves nested/cancelled-call
/// isolation; no second ambient authority or cached executable bit is added.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn admit_dispatched_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Option<AppSourceAdmission>> {
    let Some((account, claim)) = crate::provenance::current_app_claim() else {
        return Ok(None);
    };
    let admitted = admit_app_on(conn, principal, &claim).await?;
    if admitted.account != account || admitted.principal != principal {
        return Err(Error::engine("native app dispatch principal changed"));
    }
    Ok(Some(admitted))
}

/// Bind an adapter receipt to its app identity as well as its arguments.
/// These bytes are intent, not authority: admission still precedes lookup.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) fn dispatched_identity() -> Option<Value> {
    crate::provenance::current_app_claim().map(|(account, app)| {
        json!({"account":account,"package":app.package,"version":app.version,
            "install_event_id":app.install_event_id})
    })
}
