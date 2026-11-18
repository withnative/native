//! Live consent checks shared by ordinary app reads, writes and the later
//! AppDataNeeds adapter. The dispatch carries a claim, never a permission.
use super::*;
use crate::mcp::app_attribution::AppAttribution;
use crate::mcp::Caller;
use std::sync::{Arc, Mutex};

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

/// A fresh cache belongs to one pinned read scope, never to a request's
/// database/event-head key. Separate transactions can have identical heads.
#[derive(Default)]
pub(crate) struct ReadAdmissions {
    entries: Mutex<Vec<(ReadAdmissionKey, Arc<AppSourceAdmission>)>>,
}
#[derive(PartialEq, Eq)]
struct ReadAdmissionKey {
    connection: usize,
    principal: String,
    account: String,
    claim: AppAttribution,
}
tokio::task_local! {
    static READ_ADMISSIONS: Option<(usize, Arc<ReadAdmissions>)>;
}

pub(crate) async fn scope_read_admissions<F: std::future::Future>(
    connection: usize,
    admissions: Arc<ReadAdmissions>,
    work: F,
) -> F::Output {
    READ_ADMISSIONS
        .scope(Some((connection, admissions)), work)
        .await
}
pub(crate) async fn without_read_admissions<F: std::future::Future>(work: F) -> F::Output {
    READ_ADMISSIONS.scope(None, work).await
}

/// Each bounded read/mutation calls this on its actual connection. Only a
/// pinned read scope reuses successful admission; mutation admission stays live.
pub(crate) async fn admit_dispatched_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Option<Arc<AppSourceAdmission>>> {
    let Some((account, claim)) = crate::provenance::current_app_claim() else {
        return Ok(None);
    };
    let connection = crate::kernel::read_cache::connection_id(conn);
    let cache = READ_ADMISSIONS
        .try_with(|scope| match scope {
            Some((expected, _)) if *expected != connection => {
                Err(Error::engine("pinned app admission connection mismatch"))
            }
            Some((_, entries)) => Ok(Some(entries.clone())),
            None => Ok(None),
        })
        .ok()
        .transpose()?
        .flatten();
    let key = ReadAdmissionKey {
        connection,
        principal: principal.into(),
        account,
        claim: claim.as_ref().clone(),
    };
    if let Some(cache) = &cache {
        if let Some((_, admitted)) = cache
            .entries
            .lock()
            .unwrap()
            .iter()
            .find(|(entry, _)| entry == &key)
        {
            return Ok(Some(admitted.clone()));
        }
    }
    let admitted = admit_app_on(conn, principal, &claim).await?;
    if admitted.account != key.account || admitted.principal != principal {
        return Err(Error::engine("native app dispatch principal changed"));
    }
    let admitted = Arc::new(admitted);
    if let Some(cache) = cache {
        cache.entries.lock().unwrap().push((key, admitted.clone()));
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
