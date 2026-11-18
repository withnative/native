//! Person-chosen folder narrowing for one installed app (contract v2 only).
//!
//! The grant lives in the existing `kernel_app_installs` row's JSON —
//! already one per (principal, package), independent of the install
//! generation, so an app update keeps it and no v2 schema change is
//! needed. No `scope` key in the row means `all`: unscoped apps behave
//! exactly as before this feature existed. Changes arrive only through
//! `kernel.app_install_scope_set.v1` events folded onto the row.
use super::*;

pub(crate) const SCOPE_SET: &str = "kernel.app_install_scope_set.v1";

const MAX_SCOPE_FOLDERS: usize = 256;

/// One person's folder grant for one package.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AppScope {
    All,
    Folders(Vec<String>),
}

impl AppScope {
    pub(crate) fn is_scoped(&self) -> bool {
        matches!(self, AppScope::Folders(_))
    }

    pub(crate) fn folders(&self) -> Option<&[String]> {
        match self {
            AppScope::All => None,
            AppScope::Folders(ids) => Some(ids),
        }
    }

    pub(crate) fn to_json(&self) -> Value {
        match self {
            AppScope::All => json!({"kind":"all"}),
            AppScope::Folders(ids) => json!({"kind":"folders","folder_ids":ids}),
        }
    }

    /// Stable identity for read-cache keys and subscription gates.
    pub(crate) fn fingerprint(&self) -> String {
        crate::canonical_json::digest_json(&self.to_json())
    }

    /// Parse and canonicalise the contract wire shape. Folder ids are
    /// de-duplicated and sorted; existence/folder-ness is checked by the
    /// write paths, which hold a snapshot and the person.
    pub(crate) fn from_json(value: &Value) -> Result<AppScope> {
        let invalid = |message: &str| Error::engine(format!("manage_alpha_tabs: scope {message}"));
        let object = value
            .as_object()
            .ok_or_else(|| invalid("must be an object"))?;
        if object
            .keys()
            .any(|key| !matches!(key.as_str(), "kind" | "folder_ids"))
        {
            return Err(invalid("has unknown fields"));
        }
        match object.get("kind").and_then(Value::as_str) {
            Some("all") => {
                if object.contains_key("folder_ids") {
                    return Err(invalid("kind all takes no folder_ids"));
                }
                Ok(AppScope::All)
            }
            Some("folders") => {
                let ids = object
                    .get("folder_ids")
                    .and_then(Value::as_array)
                    .ok_or_else(|| invalid("folder_ids must be an array"))?;
                if ids.is_empty() || ids.len() > MAX_SCOPE_FOLDERS {
                    return Err(invalid("folder_ids must name at least one folder"));
                }
                let mut folders: Vec<String> = Vec::with_capacity(ids.len());
                for id in ids {
                    let id = id
                        .as_str()
                        .filter(|id| !id.trim().is_empty())
                        .ok_or_else(|| invalid("folder_ids must be non-empty strings"))?;
                    folders.push(id.to_owned());
                }
                folders.sort();
                folders.dedup();
                Ok(AppScope::Folders(folders))
            }
            _ => Err(invalid("kind must be all or folders")),
        }
    }

    fn from_stored(raw: &str) -> Result<AppScope> {
        let value: Value = serde_json::from_str(raw)?;
        let scope = AppScope::from_json(&value)?;
        if scope.to_json() != value {
            return Err(invalid("stored scope is not canonical"));
        }
        Ok(scope)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeSet {
    format: u32,
    package: String,
    scope: Value,
}

/// The stored grant, or `All` when the person never narrowed this package
/// (including before any install row exists).
pub(crate) async fn scope_on(
    conn: &mut SqliteConnection,
    principal: &str,
    package: &str,
) -> Result<AppScope> {
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT json_extract(row_json,'$.scope') FROM kernel_app_installs WHERE principal=? AND package=?",
    )
    .bind(principal)
    .bind(package)
    .fetch_optional(conn)
    .await?
    .flatten();
    match stored {
        Some(raw) => AppScope::from_stored(&raw),
        None => Ok(AppScope::All),
    }
}

fn is_folder(record: &KernelRecordView) -> bool {
    !record.archived
        && record.fields.get("v1_type").and_then(Value::as_str) == Some("Collection")
        && record.fields.get("v1_kind").and_then(Value::as_str) == Some("folder")
}

/// Every granted id must resolve to a live folder the person can view.
/// Unviewable and missing ids refuse identically &mdash; no existence oracle.
#[inline(never)]
pub(super) fn validate_folders_on<'a>(
    conn: &'a mut SqliteConnection,
    principal: &'a str,
    scope: &'a AppScope,
) -> futures::future::BoxFuture<'a, Result<()>> {
    Box::pin(validate_folders_inner(conn, principal, scope))
}

async fn validate_folders_inner(
    conn: &mut SqliteConnection,
    principal: &str,
    scope: &AppScope,
) -> Result<()> {
    let Some(folders) = scope.folders() else {
        return Ok(());
    };
    for folder in folders {
        let record = read_record_on(conn, principal, folder).await?;
        if !record.as_ref().is_some_and(is_folder) {
            return Err(Error::engine(
                "manage_alpha_tabs: scope folder is not a viewable folder",
            ));
        }
    }
    Ok(())
}

#[inline(never)]
fn append_scope_in<'a>(
    db: &'a Db,
    tx: &'a mut Transaction<'static, Sqlite>,
    principal: &'a str,
    package: &'a str,
    scope: &'a AppScope,
    acts: &'a mut crate::act::ActAllocation,
) -> futures::future::BoxFuture<'a, Result<()>> {
    Box::pin(append_scope_inner(db, tx, principal, package, scope, acts))
}

async fn append_scope_inner(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    principal: &str,
    package: &str,
    scope: &AppScope,
    acts: &mut crate::act::ActAllocation,
) -> Result<()> {
    append_in(
        db,
        tx,
        AppendSpec {
            record_id: aggregate(principal, package),
            event_type: SCOPE_SET.into(),
            actor: Some(principal.into()),
            payload: serde_json::to_value(ScopeSet {
                format: 1,
                package: package.into(),
                scope: scope.to_json(),
            })?,
        },
        acts,
    )
    .await?;
    Ok(())
}

/// Adoption applies its optional scope inside the adoption transaction, so
/// the app is never briefly executable unscoped. The caller has already
/// validated the folders before spending the preview receipt, and shares
/// its single act allocation with this append.
pub(super) async fn apply_adopt_scope_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    principal: &str,
    package: &str,
    scope: &AppScope,
    acts: &mut crate::act::ActAllocation,
) -> Result<()> {
    append_scope_in(db, tx, principal, package, scope, acts).await
}

/// Set (or clear, with `all`) the grant for an installed package. Takes
/// effect from the app's next call: admission and every kernel gate read
/// the projection fresh on their own snapshot.
pub(crate) async fn set_scope_as(
    db: &Db,
    principal: &str,
    package: &str,
    scope: AppScope,
) -> Result<ManagementOutcome> {
    let mut tx = begin_write(db.write_pool()).await?;
    consent::require_member(&mut tx, principal, i64::MAX).await?;
    let generation: Option<String> = sqlx::query_scalar(
        "SELECT generation FROM kernel_app_installs WHERE principal=? AND package=? AND status='installed'",
    )
    .bind(principal)
    .bind(package)
    .fetch_optional(&mut *tx)
    .await?;
    let generation =
        generation.ok_or_else(|| Error::engine("manage_alpha_tabs: installation required"))?;
    validate_folders_on(&mut tx, principal, &scope).await?;
    let changed = scope_on(&mut tx, principal, package).await? != scope;
    if changed {
        append_scope_in(
            db,
            &mut tx,
            principal,
            package,
            &scope,
            &mut crate::act::ActAllocation::new(),
        )
        .await?;
    }
    let result = management::outcome_on(&mut tx, principal, package, generation, changed).await?;
    db.commit_kernel_content(tx).await?;
    Ok(result)
}

pub(super) async fn project_scope_set(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let p: ScopeSet = event_payload(event)?;
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| invalid("scope actor missing"))?;
    if p.format != 1 || event.record_id != aggregate(actor, &p.package) {
        return Err(invalid("invalid app scope outcome"));
    }
    let scope = AppScope::from_json(&p.scope)?;
    if scope.to_json() != p.scope {
        return Err(invalid("app scope is not canonical"));
    }
    require_member_at(conn, actor, event.local_seq).await?;
    // Fold onto the existing install row; every other fold that rewrites
    // `row_json` (recorded, adopted, removed, import) preserves `$.scope`.
    let updated = sqlx::query(
        "UPDATE kernel_app_installs SET row_json=json_set(row_json,'$.scope',json(?)) WHERE principal=? AND package=?",
    )
    .bind(p.scope.to_string())
    .bind(actor)
    .bind(&p.package)
    .execute(conn)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(invalid("app scope has no install row"));
    }
    Ok(())
}

async fn require_member_at(
    conn: &mut SqliteConnection,
    principal: &str,
    before: i64,
) -> Result<()> {
    consent::require_member(conn, principal, before).await?;
    Ok(())
}

tokio::task_local! {
    /// Set by routes that admit an app without a provenance app claim
    /// (declared app-data reads, artifact-interaction effects): the
    /// admission's own scope, keyed to the principal it was admitted for.
    static SCOPE_OVERRIDE: (String, AppScope);
}

/// Run `work` with an admitted app's scope narrowing kernel gates, for the
/// routes whose caller carries no provenance app claim.
#[inline(never)]
pub(crate) fn with_scope_override<'a, F: std::future::Future + Send + 'a>(
    principal: &'a str,
    scope: AppScope,
    work: F,
) -> futures::future::BoxFuture<'a, F::Output> {
    if scope.is_scoped() {
        Box::pin(SCOPE_OVERRIDE.scope((principal.to_owned(), scope), work))
    } else {
        Box::pin(work)
    }
}

/// Synchronous scope state for the capability hot path: person and
/// unscoped dispatches (and every call after a request's first
/// resolution) decide without touching the database or the stack.
pub(crate) enum ActiveScope {
    /// Not an app dispatch, or admission-internal work.
    None,
    Known(AppScope),
    /// An app claim whose grant this request has not resolved yet.
    Unresolved(String),
}

pub(crate) fn active_scope_cached(principal: &str) -> ActiveScope {
    if let Ok((owner, scope)) = SCOPE_OVERRIDE.try_with(Clone::clone) {
        if owner == principal {
            return ActiveScope::Known(scope);
        }
    }
    let Some(package) = crate::provenance::current_app_package() else {
        return ActiveScope::None;
    };
    match super::super::read_cache::app_scope_cached(&format!("{principal}\0{package}")) {
        Some(raw) => match serde_json::from_str::<Value>(&raw)
            .ok()
            .and_then(|value| AppScope::from_json(&value).ok())
        {
            Some(scope) => ActiveScope::Known(scope),
            None => ActiveScope::Unresolved(package),
        },
        None => ActiveScope::Unresolved(package),
    }
}

/// The scope narrowing this dispatch for `principal`, if it is an app
/// dispatch at all. Resolved fresh from the projection on the caller's
/// snapshot (then cached for the request), so a `set_scope` lands on
/// the app's next call. Boxed: this sits inside capability checks on
/// already-deep dispatch stacks.
#[inline(never)]
pub(crate) fn active_scope_on<'a>(
    conn: &'a mut SqliteConnection,
    principal: &'a str,
) -> futures::future::BoxFuture<'a, Result<Option<AppScope>>> {
    Box::pin(active_scope_inner(conn, principal))
}

async fn active_scope_inner(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<Option<AppScope>> {
    match active_scope_cached(principal) {
        ActiveScope::None => Ok(None),
        ActiveScope::Known(scope) => Ok(Some(scope)),
        ActiveScope::Unresolved(package) => {
            let scope = scope_on(conn, principal, &package).await?;
            super::super::read_cache::app_scope_put(
                format!("{principal}\0{package}"),
                scope.to_json().to_string(),
            );
            Ok(Some(scope))
        }
    }
}

/// Fingerprint of the scope narrowing `principal` on this dispatch, for
/// read-cache keys. `None` when this is not an app dispatch.
#[inline(never)]
pub(crate) fn active_fingerprint_on<'a>(
    conn: &'a mut SqliteConnection,
    principal: &'a str,
) -> futures::future::BoxFuture<'a, Result<Option<String>>> {
    Box::pin(async move {
        Ok(active_scope_on(conn, principal)
            .await?
            .map(|scope| scope.fingerprint()))
    })
}
