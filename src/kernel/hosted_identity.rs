//! Host-only catalogue admission for imported v2 workspaces.
//!
//! No MCP arguments reach this boundary. The host reads its catalogue while
//! holding the workspace write lock, so an older concurrent snapshot cannot
//! overwrite a newer admission. The catalogue remains the membership authority.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::{cell::RefCell, collections::HashMap, sync::Arc};

pub mod offboarding;
tokio::task_local! {
    static REQUEST_ROSTERS: RefCell<HashMap<String, Arc<Roster>>>;
}
pub(crate) async fn scope_request<F: Future>(future: F) -> F::Output {
    if REQUEST_ROSTERS.try_with(|_| ()).is_ok() {
        future.await
    } else {
        REQUEST_ROSTERS
            .scope(RefCell::new(HashMap::new()), future)
            .await
    }
}

// Both absent-roster and policy-template lookups must stay indexed even when
// a root retains tens of thousands of imported history events.
pub(crate) const EVENT_INDEX_DDL: &str = "CREATE INDEX IF NOT EXISTS idx_kernel_hosted_event_lookup ON content_events(record_id,type,seq)";

pub(crate) const ROSTER_EVENT: &str = "kernel.hosted_membership.v1";
pub(crate) const IDENTITY_EVENT: &str = "kernel.import_hosted_accounts.v1";
pub(crate) const POLICY_EVENT: &str = "kernel.import_member_policy.v1";

/// A complete, freshly read catalogue roster and the authenticated actor's
/// catalogue account ID. Guests are excluded from membership; identity resolution belongs to the
/// catalogue, never to kernel principal labels or caller-supplied arguments.
pub struct VerifiedHostedMembership {
    account: String,
    members: BTreeSet<String>,
    catalog_users: Option<BTreeMap<String, String>>,
    catalog_directory: BTreeMap<String, String>,
}
impl VerifiedHostedMembership {
    /// # Safety
    /// Supply the authenticated catalogue user ID and the complete active
    /// owner/member roster (catalogue user ID -> verified catalogue email) for
    /// this exact routed database, including offboarding fences. Tool arguments
    /// must never supply these facts. On initial activation also supply the
    /// catalogue directory, so imported identities can be pinned even for
    /// people currently outside workspace membership. Unrelated directory
    /// entries are discarded. Read these facts inside admission.
    pub unsafe fn from_catalog_unchecked(
        account: String,
        users: BTreeMap<String, String>,
        catalog_directory: BTreeMap<String, String>,
    ) -> Self {
        Self {
            account,
            members: users.keys().cloned().collect(),
            catalog_users: Some(users),
            catalog_directory,
        }
    }

    /// Synthetic harness for already resolved portable bindings.
    /// # Safety
    /// The fixture must supply its complete authoritative account roster.
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    pub(crate) unsafe fn from_accounts_unchecked(
        account: String,
        members: BTreeSet<String>,
    ) -> Self {
        Self {
            account,
            members,
            catalog_users: None,
            catalog_directory: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedAccounts {
    // Not a secret: this digest is only a sealed migration lookup key. It is
    // never accepted as authentication and is not exposed by logical SQL.
    emails: BTreeMap<String, String>,
    salt: String,
}
fn email_key(email: &str, salt: &str) -> Result<String> {
    let normalized = crate::identity::normalize_identifier("email", &email.trim().to_lowercase())?;
    Ok(format!(
        "{:x}",
        Sha256::digest(format!("hosted-identity-v1:{salt}:{normalized}").as_bytes())
    ))
}

pub(crate) async fn import_accounts(
    db: &Db,
    host: &str,
    emails: Vec<(String, String)>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    let live: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type=?)",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(ROSTER_EVENT)
    .fetch_one(&mut *tx)
    .await?;
    if live {
        return Err(Error::engine(
            "cannot import hosted identities after activation",
        ));
    }
    let previous: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1")
        .bind(KERNEL_ROOT_ID).bind(IDENTITY_EVENT).fetch_optional(&mut *tx).await?;
    // Stable per import lineage, different across databases; not a secret key.
    let salt = previous
        .as_ref()
        .map(|p| serde_json::from_str::<ImportedAccounts>(p))
        .transpose()?
        .map(|p| p.salt)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut accounts = BTreeMap::new();
    for (email, account) in emails {
        let key = email_key(&email, &salt)?;
        if accounts
            .insert(key, account.clone())
            .is_some_and(|old| old != account)
        {
            return Err(Error::engine("ambiguous imported hosted email binding"));
        }
    }
    let payload = serde_json::to_value(ImportedAccounts {
        emails: accounts,
        salt,
    })?;

    if previous
        .map(|p| serde_json::from_str::<serde_json::Value>(&p))
        .transpose()?
        .as_ref()
        == Some(&payload)
    {
        return Ok(());
    }
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: IDENTITY_EVENT.into(),
            payload,
            actor: Some(host.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Roster {
    // Account binding -> kernel principal. Emails are deliberately not stored.
    members: BTreeMap<String, String>,
    // Retain removed identities: email changes/reuse cannot rebind them.
    catalog_accounts: BTreeMap<String, String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MemberPolicy {
    policy_seq: i64,
    explicit: BTreeMap<String, String>,
    members: Option<String>,
}

async fn policy_seq_before(conn: &mut SqliteConnection, home: &str, before: i64) -> Result<i64> {
    Ok(sqlx::query_scalar("SELECT coalesce(max(seq),0) FROM main.content_events WHERE record_id=? AND seq<? AND type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')")
        .bind(home).bind(before).fetch_one(conn).await?)
}

/// Preserve the source distinction before expanded grants become ambiguous.
/// Called only by the importer, after restoring its final policies.
pub(crate) async fn import_policy(
    db: &Db,
    host: &str,
    home: &str,
    explicit: BTreeMap<String, String>,
    members: Option<String>,
) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    hq::require_import(&mut tx, host).await?;
    hq::require_source_import_open(&mut tx).await?;
    let payload = MemberPolicy {
        policy_seq: policy_seq_before(&mut tx, home, i64::MAX).await?,
        explicit,
        members,
    };
    let mut acts = crate::act::ActAllocation::new();
    append_in(
        db,
        &mut tx,
        AppendSpec {
            record_id: home.into(),
            event_type: POLICY_EVENT.into(),
            payload: serde_json::to_value(payload)?,
            actor: Some(host.into()),
        },
        &mut acts,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Resolve/mint the authenticated account and produce KernelV2's bare account
/// credential. Invoke on every hosted request, before dispatch; never cache a
/// Caller across admissions. `load` reads the catalogue inside this call; its
/// boolean argument requests the one-time complete identity directory. The
/// directory is used only to pin already imported accounts, never as a roster.
/// It must return a complete roster even when the actor was removed/a guest:
/// removals are committed before the actor's admission is refused.
pub async fn reconcile_hosted_caller<F, Fut>(db: &Db, load: F) -> Result<crate::mcp::Caller>
where
    F: FnOnce(bool) -> Fut,
    Fut: Future<Output = Result<VerifiedHostedMembership>>,
{
    let mut tx = begin_write(db.write_pool()).await?;
    let previous_roster = roster_on(&mut tx).await?;
    let mut verified = load(previous_roster.is_none()).await?;
    if verified
        .members
        .iter()
        .chain(std::iter::once(&verified.account))
        .any(|a| a.trim().is_empty() || a.starts_with("host:"))
    {
        return Err(Error::auth("invalid hosted catalogue account"));
    }
    // A refused guest/nonmember cannot activate a workspace or end its import
    // window. Once live, refresh exclusions before refusing a removed actor.
    if !verified.members.contains(&verified.account) && previous_roster.is_none() {
        return Err(Error::engine("database membership not found"));
    }
    // Refuse old imports whose expanded grants have no source provenance.
    let missing: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_policies p WHERE EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=p.root_id AND e.type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1')) AND NOT EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=p.root_id AND e.type=?))")
        .bind(POLICY_EVENT).fetch_one(&mut *tx).await?;
    if missing {
        return Err(Error::engine(
            "hosted v2 requires member-policy provenance; reimport before cutover",
        ));
    }
    let host: String =
        sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals WHERE auth_binding=?")
            .bind(hq::HOST_IMPORT_BINDING)
            .fetch_one(&mut *tx)
            .await?;
    let first = previous_roster.is_none();
    let mut catalog_accounts = previous_roster
        .map(|r| r.catalog_accounts.clone())
        .unwrap_or_default();
    if let Some(users) = verified.catalog_users.take() {
        let raw: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1")
            .bind(KERNEL_ROOT_ID).bind(IDENTITY_EVENT).fetch_optional(&mut *tx).await?;
        let imported: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.import_members_roster.v1')")
            .bind(KERNEL_ROOT_ID).fetch_one(&mut *tx).await?;
        if imported && raw.is_none() {
            return Err(Error::engine(
                "hosted v2 requires imported identity provenance; reimport before cutover",
            ));
        }
        let imported_accounts = raw
            .map(|p| serde_json::from_str::<ImportedAccounts>(&p))
            .transpose()?;
        let (aliases, salt) = imported_accounts
            .map(|p| (p.emails, p.salt))
            .unwrap_or_default();
        if first {
            // Match only already imported identities. Inactive people gain no
            // membership or new principal; their immutable catalogue ID is
            // pinned so a legitimate later join can recover the old identity.
            for (catalog_id, email) in &verified.catalog_directory {
                if let Some(binding) = aliases.get(&email_key(email, &salt)?) {
                    if catalog_accounts.values().any(|a| a == binding) {
                        return Err(Error::auth(
                            "multiple catalogue identities map to one imported account",
                        ));
                    }
                    catalog_accounts.insert(catalog_id.clone(), binding.clone());
                }
            }
        }
        for (catalog_id, email) in &users {
            if !catalog_accounts.contains_key(catalog_id) {
                // Email is v1's verified migration evidence only at activation.
                // Thereafter, a different catalogue ID never inherits an old
                // principal through a changed/reused email address.
                let binding = if first {
                    aliases.get(&email_key(email, &salt)?).cloned()
                } else {
                    None
                }
                .unwrap_or_else(|| catalog_id.clone());
                if catalog_accounts.values().any(|a| a == &binding) {
                    return Err(Error::auth(
                        "multiple catalogue identities map to one imported account",
                    ));
                }
                catalog_accounts.insert(catalog_id.clone(), binding);
            }
        }
        verified.members = users
            .keys()
            .map(|id| catalog_accounts[id].clone())
            .collect();
        verified.account = catalog_accounts
            .get(&verified.account)
            .cloned()
            .ok_or_else(|| Error::engine("database membership not found"))?;
    }
    let mut members = BTreeMap::new();
    let mut acts = crate::act::ActAllocation::new();
    for account in &verified.members {
        let existing: Option<(String, String)> = sqlx::query_as(
            "SELECT principal_id,kind FROM main.kernel_principals WHERE auth_binding=?",
        )
        .bind(account)
        .fetch_optional(&mut *tx)
        .await?;
        let id = match existing {
            Some((id, kind)) if kind == "account" => id,
            Some(_) => return Err(Error::auth("hosted binding is not an account principal")),
            None => {
                let id = Uuid::new_v4().to_string();
                append_in(db, &mut tx, AppendSpec {
                    record_id: id.clone(), event_type: KERNEL_PRINCIPAL_CREATED_EVENT.into(),
                    payload: serde_json::json!({"kind":"account", "display_label":"Hosted member", "auth_binding":account}),
                    actor: Some(host.clone()),
                }, &mut acts).await?;
                id
            }
        };
        members.insert(account.clone(), id);
    }
    let payload = serde_json::to_value(Roster {
        members,
        catalog_accounts,
    })?;
    let previous: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(ROSTER_EVENT)
    .fetch_optional(&mut *tx)
    .await?;
    if previous
        .map(|p| serde_json::from_str::<serde_json::Value>(&p))
        .transpose()?
        .as_ref()
        != Some(&payload)
    {
        append_in(
            db,
            &mut tx,
            AppendSpec {
                record_id: KERNEL_ROOT_ID.into(),
                event_type: ROSTER_EVENT.into(),
                payload,
                actor: Some(host),
            },
            &mut acts,
        )
        .await?;
    }
    tx.commit().await?;
    if !verified.members.contains(&verified.account) {
        return Err(Error::engine("database membership not found"));
    }
    Ok(crate::mcp::Caller::authenticated(verified.account))
}

// Logical SQL installs a temp.content_events relation. Authority always reads main.
async fn roster_on(conn: &mut SqliteConnection) -> Result<Option<Arc<Roster>>> {
    roster_before(conn, i64::MAX).await
}
async fn roster_before(conn: &mut SqliteConnection, before: i64) -> Result<Option<Arc<Roster>>> {
    let raw: Option<(String, String)> = sqlx::query_as(
        "SELECT id,payload FROM main.content_events WHERE record_id=? AND type=? AND seq<? ORDER BY seq DESC LIMIT 1",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(ROSTER_EVENT)
    .bind(before)
    .fetch_optional(conn)
    .await?;
    let Some((id, raw)) = raw else {
        return Ok(None);
    };
    if let Some(cached) = REQUEST_ROSTERS
        .try_with(|c| c.borrow().get(&id).cloned())
        .ok()
        .flatten()
    {
        return Ok(Some(cached));
    }
    let parsed = Arc::new(serde_json::from_str::<Roster>(&raw)?);
    let _ = REQUEST_ROSTERS.try_with(|c| c.borrow_mut().insert(id, parsed.clone()));
    Ok(Some(parsed))
}

/// FrozenRead admission: SELECT-only, even on a physically read-only handle.
/// The host still supplies current catalogue fences. Only already pinned,
/// admitted members can use the last projected roster; joins wait for thaw.
pub async fn reconcile_hosted_caller_read_only<F, Fut>(
    db: &Db,
    load: F,
) -> Result<crate::mcp::Caller>
where
    F: FnOnce(bool) -> Fut,
    Fut: Future<Output = Result<VerifiedHostedMembership>>,
{
    let mut snapshot = db.pool().begin().await?;
    let roster = roster_on(&mut snapshot).await?;
    let verified = load(false).await?;
    if verified.account.trim().is_empty() || verified.account.starts_with("host:") {
        return Err(Error::auth("invalid hosted catalogue account"));
    }
    if !verified.members.contains(&verified.account) {
        return Err(Error::engine("database membership not found"));
    }
    let wait =
        || Error::engine("hosted v2 identity admission waits until the database is unfrozen");
    let roster = roster.ok_or_else(wait)?;
    let account = roster
        .catalog_accounts
        .get(&verified.account)
        .ok_or_else(wait)?;
    let id = roster.members.get(account).ok_or_else(wait)?;
    let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding=? AND kind='account')")
        .bind(id).bind(account).fetch_one(&mut *snapshot).await?;
    if !valid {
        return Err(Error::auth("invalid pinned hosted identity"));
    }
    Ok(crate::mcp::Caller::authenticated(account.clone()))
}

// Membership is a workspace-wide admission fence, before even owner floors.
// Reserved host services remain usable; they cannot be authenticated accounts.
pub(crate) async fn admitted(conn: &mut SqliteConnection, principal: &str) -> Result<bool> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(true);
    };
    let host: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding IN ('host:v1-import','host:relates-to:transform'))")
        .bind(principal).fetch_one(conn).await?;
    Ok(host || roster.members.values().any(|id| id == principal))
}

/// Personal app consent requires an account admitted at the outcome's position.
/// Host services are excluded. Admission uses the latest roster strictly
/// before that position; later roster changes do not alter historical outcomes.
pub(crate) async fn account_admitted_before(
    conn: &mut SqliteConnection,
    principal: &str,
    before: i64,
) -> Result<bool> {
    let Some(roster) = roster_before(conn, before).await? else {
        return Ok(false);
    };
    let account: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND kind='account')",
    )
    .bind(principal)
    .fetch_one(conn)
    .await?;
    Ok(account && roster.members.values().any(|id| id == principal))
}

/// A hosted catalogue ID and the imported portable binding can differ. Use
/// the immutable H3 mapping and current roster together, never string equality
/// between the catalogue identity and Caller::credential().
pub(crate) async fn catalog_account_matches_on(
    conn: &mut SqliteConnection,
    catalog_account: &str,
    account_binding: &str,
    principal: &str,
) -> Result<bool> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(false);
    };
    Ok(roster
        .catalog_accounts
        .get(catalog_account)
        .map(String::as_str)
        == Some(account_binding)
        && roster.members.get(account_binding).map(String::as_str) == Some(principal))
}

/// Read the immutable H3 catalogue mapping without provisioning or email matching.
/// The host must pass current catalogue members only and separately authorize
/// directory access and any Person record. Retained mappings for former members
/// are filtered against the current admitted roster as a second check.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn catalog_account_on(
    conn: &mut SqliteConnection,
    catalog_account: &str,
) -> Result<Option<String>> {
    Ok(roster_on(conn).await?.and_then(|roster| {
        roster
            .catalog_accounts
            .get(catalog_account)
            .filter(|account| roster.members.contains_key(*account))
            .cloned()
    }))
}

pub(crate) async fn policy_rows(
    conn: &mut SqliteConnection,
    principal: &str,
    home: &str,
) -> Result<Option<Vec<(String, String, String, String)>>> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(None);
    };
    let raw: Option<(i64, String)> = sqlx::query_as(
        "SELECT seq,payload FROM main.content_events WHERE type=? AND record_id=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(POLICY_EVENT)
    .bind(home)
    .fetch_optional(&mut *conn)
    .await?;
    let Some((_template_seq, raw)) = raw else {
        return Ok(None);
    };
    let mut p: MemberPolicy = serde_json::from_str(&raw)?;
    if p.policy_seq != policy_seq_before(conn, home, i64::MAX).await? {
        return Ok(None);
    }
    // Cleanup deletes the physical account row. Keep import provenance only
    // while that row still exists: rejoin can restore the member baseline,
    // never a removed explicit grant. This also follows projection replay
    // order, unlike scanning future cleanup events from the immutable log.
    let subjects: BTreeSet<String> = sqlx::query_scalar("SELECT subject_id FROM main.kernel_policy_entries WHERE root_id=? AND subject_kind='account'")
        .bind(home).fetch_all(&mut *conn).await?.into_iter().collect();
    p.explicit.retain(|id, _| subjects.contains(id));
    let mut rows: Vec<_> = p
        .explicit
        .into_iter()
        .map(|(id, cap)| ("account".into(), id, "allow".into(), cap))
        .collect();
    if roster.members.values().any(|id| id == principal) {
        if let Some(cap) = p.members {
            rows.push(("account".into(), principal.into(), "allow".into(), cap));
        }
    }
    Ok(Some(rows))
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    if event.event_type == offboarding::EVENT {
        return offboarding::project(conn, event).await;
    }
    if event.event_type == IDENTITY_EVENT {
        if event.record_id != KERNEL_ROOT_ID {
            return Err(Error::engine("invalid imported identity target"));
        }
        let live: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type=? AND seq<?)")
            .bind(KERNEL_ROOT_ID).bind(ROSTER_EVENT).bind(event.local_seq).fetch_one(&mut *conn).await?;
        if live {
            return Err(Error::engine(
                "cannot import hosted identities after activation",
            ));
        }
        let p: ImportedAccounts = event_payload(event)?;
        if Uuid::parse_str(&p.salt).is_err() {
            return Err(Error::engine("invalid imported hosted identity salt"));
        }
        for (key, account) in p.emails {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE auth_binding=? AND kind='account')").bind(&account).fetch_one(&mut *conn).await?;
            if !valid || key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::engine("invalid imported hosted binding"));
            }
        }
        return Ok(());
    }
    if event.event_type == ROSTER_EVENT {
        let p: Roster = event_payload(event)?;
        if event.record_id != KERNEL_ROOT_ID {
            return Err(Error::engine("invalid hosted roster target"));
        }
        if p.catalog_accounts
            .keys()
            .any(|id| id.trim().is_empty() || id.starts_with("host:"))
            || p.catalog_accounts.values().collect::<BTreeSet<_>>().len()
                != p.catalog_accounts.len()
        {
            return Err(Error::engine("invalid catalogue account mapping"));
        }
        let previous: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type=? AND seq<? ORDER BY seq DESC LIMIT 1")
            .bind(KERNEL_ROOT_ID).bind(ROSTER_EVENT).bind(event.local_seq).fetch_optional(&mut *conn).await?;
        if let Some(raw) = previous {
            let old: Roster = serde_json::from_str(&raw)?;
            if old
                .catalog_accounts
                .iter()
                .any(|(id, account)| p.catalog_accounts.get(id) != Some(account))
            {
                return Err(Error::engine("catalogue account bindings are immutable"));
            }
        }
        for (account, id) in p.members {
            let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding=? AND kind='account')")
                .bind(id).bind(&account).fetch_one(&mut *conn).await?;
            if !valid || account.starts_with("host:") {
                return Err(Error::engine("invalid hosted roster binding"));
            }
        }
    } else {
        let p: MemberPolicy = event_payload(event)?;
        if p.policy_seq == 0
            || p.policy_seq != policy_seq_before(conn, &event.record_id, event.local_seq).await?
        {
            return Err(Error::engine("invalid member policy provenance"));
        }
        for cap in p.explicit.values().chain(p.members.iter()) {
            parse_kernel_capability(cap)?;
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests;
