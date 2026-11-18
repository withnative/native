//! Host-only catalogue admission for imported v2 workspaces.
//!
//! No MCP arguments reach this boundary. The host reads its catalogue while
//! holding the workspace write lock before changing state, so an older
//! concurrent snapshot cannot overwrite a newer admission. Established
//! unchanged rosters may be admitted in a read snapshot. The catalogue remains
//! the membership authority.
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::{cell::RefCell, collections::HashMap, sync::Arc};

/// The real display name of an account principal as `viewer` may see it: the
/// title of the Person the account is linked to (v1 account directory, else the
/// hosted messaging link), read through the viewer's own record visibility
/// exactly as the `viewer`/`actors` SQL views do. Account labels are never
/// consulted (hosted ones are generic). `None` when there is no visible Person
/// or the title is blank, an email, or an id/binding, so callers fall back
/// instead of exposing it.
pub(crate) async fn visible_account_name_on(
    conn: &mut SqliteConnection,
    viewer: &str,
    principal: &str,
    binding: &str,
) -> Result<Option<String>> {
    let person: Option<String> = sqlx::query_scalar(
        "SELECT coalesce((SELECT d.record_id FROM main.kernel_v1_state d WHERE d.section='account_directory' AND d.account_principal=?1 ORDER BY d.source_id LIMIT 1),(SELECT m.person_id FROM main.kernel_message_people m WHERE m.principal_id=?1))",
    )
    .bind(principal)
    .fetch_one(&mut *conn)
    .await?;
    let Some(person) = person else {
        return Ok(None);
    };
    let Some(record) = read_record_on(conn, viewer, &person).await? else {
        return Ok(None);
    };
    let title = record
        .fields
        .get("title")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .unwrap_or("");
    if title.is_empty()
        || title.contains('@')
        || title == binding
        || title == principal
        || title == person
        || Uuid::parse_str(title).is_ok()
    {
        return Ok(None);
    }
    Ok(Some(title.to_owned()))
}

pub mod offboarding;
// Slice 2a stores bundles but no production path reads them yet; the readers
// below are exercised only by probe-gated tests, so liveness is enforced
// exactly there and allowed everywhere else for now.
#[cfg_attr(not(all(test, feature = "v2-kernel-probe")), allow(dead_code))]
pub(crate) mod bundles;
tokio::task_local! {
    static REQUEST_ROSTERS: RefCell<HashMap<String, Arc<Roster>>>;
    // Set only by the closed notification-creation capability reader below.
    // Ordinary reads and delivery revalidation retain their current horizon.
    static NOTIFICATION_CREATION_BEFORE: i64;
}
pub(crate) async fn scope_request<F: Future>(future: F) -> F::Output {
    if REQUEST_ROSTERS.try_with(|_| ()).is_ok() {
        future.await
    } else {
        REQUEST_ROSTERS
            .scope(
                RefCell::new(HashMap::new()),
                bundles::scope_view_request(future),
            )
            .await
    }
}

fn read_before() -> i64 {
    NOTIFICATION_CREATION_BEFORE
        .try_with(|before| *before)
        .unwrap_or(i64::MAX)
}

/// Creation is a historical decision even on the live fold. Projections on
/// `conn` already represent the preceding state, but hosted roster/templates
/// are read directly from the immutable log and must share that same horizon.
/// This closed scope cannot be selected by an MCP caller or used for delivery.
pub(super) async fn notification_creation_capability_on(
    conn: &mut SqliteConnection,
    principal: &str,
    event: &EventRow,
) -> Result<Capability> {
    NOTIFICATION_CREATION_BEFORE
        .scope(
            event.local_seq,
            super::kernel_effective_capability_uncached_on(conn, principal, &event.record_id),
        )
        .await
}

/// Historical capability of `principal` on `target` as of `event`: roster and
/// member-policy template are read strictly before `event.local_seq`, so a
/// writer who later leaves the roster or loses access never invalidates an
/// earlier legitimate event during full, tail or standby replay. Closed scope,
/// uncached; not reachable from an MCP caller.
pub(crate) async fn capability_at_event_on(
    conn: &mut SqliteConnection,
    principal: &str,
    target: &str,
    event: &EventRow,
) -> Result<Capability> {
    NOTIFICATION_CREATION_BEFORE
        .scope(
            event.local_seq,
            super::kernel_effective_capability_uncached_on(conn, principal, target),
        )
        .await
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
    expected_catalog_accounts: Option<BTreeMap<String, String>>,
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
            expected_catalog_accounts: None,
        }
    }

    /// Tighten staging admission with the v1 resolver's independently checked
    /// accounts. This grants nothing; a different kernel mapping refuses before
    /// any principal or roster write, in the same kernel transaction.
    pub fn requiring_catalog_accounts(mut self, expected: BTreeMap<String, String>) -> Self {
        self.expected_catalog_accounts = Some(expected);
        self
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
            expected_catalog_accounts: None,
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

fn template_from_event(seq: i64, event_type: &str, raw: &str) -> Result<Option<MemberPolicy>> {
    if event_type == POLICY_EVENT {
        return Ok(Some(serde_json::from_str(raw)?));
    }
    let policy: KernelPolicyReplacedPayload = serde_json::from_str(raw)?;
    let Some(metadata) = policy.record_policy else {
        return Ok(None);
    };
    if metadata.inherit {
        return Ok(None);
    }
    Ok(Some(MemberPolicy {
        policy_seq: seq,
        explicit: policy
            .entries
            .into_iter()
            .map(|e| (e.subject_id, e.capability))
            .collect(),
        members: metadata.members,
    }))
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

/// Savepoint fencing one bundle-seeding attempt inside the admission
/// transaction. A refused bundle event's inserted row must not survive in a
/// transaction that still commits: the kernel append inserts the event row
/// before projecting it, so a projection refusal leaves the row behind.
/// The savepoint makes the seed set all-or-nothing; the roster statements
/// that follow in the same transaction are unaffected.
const BUNDLE_SEED_SAVEPOINT: &str = "native_bundle_seed";

#[cfg(all(test, feature = "v2-kernel-probe"))]
tokio::task_local! {
    static BREAK_BUNDLE_SEED_ROLLBACK: ();
}

/// Scope a broken bundle-seed rollback to the wrapped future. Test-only:
/// while scoped, the seed rollback targets a savepoint that was never
/// taken, so it fails the way a storage-level auto-rollback would.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn with_broken_bundle_seed_rollback<F: Future>(future: F) -> F::Output {
    BREAK_BUNDLE_SEED_ROLLBACK.scope((), future).await
}

async fn rollback_bundle_seed(tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>) -> Result<()> {
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    let savepoint = if BREAK_BUNDLE_SEED_ROLLBACK.try_with(|_| ()).is_ok() {
        "native_bundle_seed_missing"
    } else {
        BUNDLE_SEED_SAVEPOINT
    };
    #[cfg(not(all(test, feature = "v2-kernel-probe")))]
    let savepoint = BUNDLE_SEED_SAVEPOINT;
    sqlx::query(&format!("ROLLBACK TO {savepoint}"))
        .execute(&mut **tx)
        .await?;
    sqlx::query(&format!("RELEASE {savepoint}"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Seed pre-2a databases inside the admission transaction.
///
/// A plain seeding failure (projection refusal, validation, ...) rolls the
/// seed set back to its savepoint and admission proceeds with a warning:
/// nothing reads bundles yet, the act memo is restored when it held nothing
/// on entry (the relationship persistence precedent — a bump can only have
/// happened inside the savepoint then, so the rollback revoked exactly the
/// memoized value), and the next admission retries idempotently.
///
/// If the rollback itself fails, the transaction is no longer the one the
/// admission holds the write lock for: SQLite has auto-rolled back to
/// autocommit (FULL/IOERR/NOMEM) or the connection is otherwise broken.
/// Continuing would run the roster appends outside the write lock,
/// committing one statement at a time and failing at the final commit — a
/// partial write. So the rollback error fails admission fast instead of
/// logging and continuing.
async fn seed_bundles_rolled_back_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    host: &str,
    acts: &mut crate::act::ActAllocation,
) -> Result<()> {
    sqlx::query(&format!("SAVEPOINT {BUNDLE_SEED_SAVEPOINT}"))
        .execute(&mut **tx)
        .await?;
    let prior_act = acts.get();
    match bundles::seed_bundles_in(db, &mut *tx, host, acts).await {
        Ok(()) => {
            sqlx::query(&format!("RELEASE {BUNDLE_SEED_SAVEPOINT}"))
                .execute(&mut **tx)
                .await?;
            Ok(())
        }
        Err(error) => {
            rollback_bundle_seed(tx).await.map_err(|rollback| {
                Error::engine(format!(
                    "bundle seed rollback failed after {error}: {rollback}"
                ))
            })?;
            if prior_act.is_none() {
                acts.reset();
            }
            tracing::warn!(error = %error, "membership bundle seeding failed; continuing admission");
            Ok(())
        }
    }
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
    if let Some(expected) = &verified.expected_catalog_accounts {
        let mismatches = expected
            .iter()
            .filter(|(id, account)| catalog_accounts.get(*id) != Some(*account))
            .count();
        if mismatches > 0 {
            return Err(Error::engine(format!(
                "catalog roster resolution; class=kernel_account_map_mismatch count={mismatches}"
            )));
        }
    }
    let mut members = BTreeMap::new();
    let mut acts = crate::act::ActAllocation::new();
    // Slice 2b: seed databases created before 2a. Same write lock (this
    // transaction), same host-importer actor, idempotent. Seeding reads
    // nothing the admission decides on. A contained seeding failure logs
    // and admission proceeds because nothing reads bundles yet; a failed
    // seed rollback fails admission (see `seed_bundles_rolled_back_in`).
    seed_bundles_rolled_back_in(db, &mut tx, &host, &mut acts).await?;
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
    roster_before(conn, read_before()).await
}
/// Hosted member copies require an existing, valid activation roster. Unlike
/// ordinary kernel reads, an unactivated standalone database is not eligible.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn activated_on(conn: &mut SqliteConnection) -> Result<bool> {
    Ok(roster_on(conn).await?.is_some())
}

async fn roster_before(conn: &mut SqliteConnection, before: i64) -> Result<Option<Arc<Roster>>> {
    // Admission reads v1 only, exactly as on main. A future v2 write must not
    // change who is admitted until every v1-scoped fence moves with it; see
    // the preconditions listed on `bundles::ROSTER_V2_EVENT`. Bundle ids live
    // in `bundles::roster_view_before`, which nothing in admission or
    // authorization may call.
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
    #[cfg(test)]
    let parse_started = std::time::Instant::now();
    let parsed = Arc::new(serde_json::from_str::<Roster>(&raw)?);
    #[cfg(test)]
    roster_parse_probe::record(parse_started.elapsed());
    let _ = REQUEST_ROSTERS.try_with(|c| c.borrow_mut().insert(id, parsed.clone()));
    Ok(Some(parsed))
}

/// Try ordinary established admission without taking the workspace writer.
/// `None` requires the original writer path with a NEW catalogue read after
/// acquiring its lock. Never upgrade this snapshot or reuse its host facts.
/// Unlike frozen admission, every member and seed must already be reconciled.
/// This reads only the current v1 roster; bundles carry no admission authority.
pub async fn try_reconcile_hosted_caller_read_only<F, Fut>(
    db: &Db,
    load: F,
) -> Result<Option<crate::mcp::Caller>>
where
    F: FnOnce(bool) -> Fut,
    Fut: Future<Output = Result<VerifiedHostedMembership>>,
{
    // Read catalogue facts before pinning the workspace snapshot. A removed
    // then re-added member must not match an older full roster while the live
    // workspace already contains a persisted exclusion.
    let verified = load(false).await?;
    let mut snapshot = db.pool().begin().await?;
    let Some(roster) = roster_on(&mut snapshot).await? else {
        return Ok(None);
    };
    if verified
        .members
        .iter()
        .chain(std::iter::once(&verified.account))
        .any(|a| a.trim().is_empty() || a.starts_with("host:"))
    {
        return Err(Error::auth("invalid hosted catalogue account"));
    }
    // A removed actor also falls back: ordinary admission must persist the
    // complete exclusion roster before returning a membership refusal.
    if !verified.members.contains(&verified.account) {
        return Ok(None);
    }
    if roster
        .catalog_accounts
        .keys()
        .any(|id| id.trim().is_empty() || id.starts_with("host:"))
        || roster
            .catalog_accounts
            .values()
            .collect::<BTreeSet<_>>()
            .len()
            != roster.catalog_accounts.len()
        || roster
            .members
            .keys()
            .any(|a| a.trim().is_empty() || a.starts_with("host:"))
    {
        return Err(Error::auth("invalid pinned hosted identity"));
    }
    let members = if let Some(users) = &verified.catalog_users {
        let Some(accounts) = users
            .keys()
            .map(|id| roster.catalog_accounts.get(id).cloned())
            .collect::<Option<BTreeSet<_>>>()
        else {
            return Ok(None);
        };
        accounts
    } else {
        verified.members.clone()
    };
    if members != roster.members.keys().cloned().collect() {
        return Ok(None);
    }
    if let Some(expected) = &verified.expected_catalog_accounts {
        if expected
            .iter()
            .any(|(id, account)| roster.catalog_accounts.get(id) != Some(account))
        {
            return Ok(None);
        }
    }
    // Match the writer's provenance refusal even after activation. Imported
    // identities are immutable, but their provenance must still be present.
    let missing_policy: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_policies p WHERE EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=p.root_id AND e.type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1')) AND NOT EXISTS(SELECT 1 FROM main.content_events e WHERE e.record_id=p.root_id AND e.type=?))")
        .bind(POLICY_EVENT).fetch_one(&mut *snapshot).await?;
    if missing_policy {
        return Err(Error::engine(
            "hosted v2 requires member-policy provenance; reimport before cutover",
        ));
    }
    if verified.catalog_users.is_some() {
        let missing_identity: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type='kernel.import_members_roster.v1') AND NOT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type=?)")
            .bind(KERNEL_ROOT_ID).bind(KERNEL_ROOT_ID).bind(IDENTITY_EVENT)
            .fetch_one(&mut *snapshot).await?;
        if missing_identity {
            return Err(Error::engine(
                "hosted v2 requires imported identity provenance; reimport before cutover",
            ));
        }
        // Keep malformed provenance a refusal just as in the writer path.
        let raw: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type=? ORDER BY seq DESC LIMIT 1")
            .bind(KERNEL_ROOT_ID).bind(IDENTITY_EVENT).fetch_optional(&mut *snapshot).await?;
        if let Some(raw) = raw {
            serde_json::from_str::<ImportedAccounts>(&raw)?;
        }
    }
    // The writer always requires its host-import principal, even for a no-op.
    let _: String =
        sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals WHERE auth_binding=?")
            .bind(hq::HOST_IMPORT_BINDING)
            .fetch_one(&mut *snapshot)
            .await?;
    for (account, id) in &roster.members {
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding=? AND kind='account')")
            .bind(id).bind(account).fetch_one(&mut *snapshot).await?;
        if !valid {
            // The writer resolves by auth_binding and may repair a stale
            // roster principal ID or mint a missing account. Let that path
            // decide; a binding to a non-account principal still refuses.
            return Ok(None);
        }
    }
    for id in [
        bundles::OWNER_BUNDLE_ID,
        bundles::MEMBER_BUNDLE_ID,
        bundles::GUEST_BUNDLE_ID,
    ] {
        let seeded: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type=? AND json_extract(payload,'$.id')=?)")
            .bind(KERNEL_ROOT_ID).bind(bundles::BUNDLE_DEFINED_EVENT).bind(id)
            .fetch_one(&mut *snapshot).await?;
        if !seeded {
            return Ok(None);
        }
    }
    let account = if verified.catalog_users.is_some() {
        roster
            .catalog_accounts
            .get(&verified.account)
            .ok_or_else(|| Error::auth("invalid pinned hosted identity"))?
            .clone()
    } else {
        verified.account
    };
    snapshot.rollback().await?;
    Ok(Some(crate::mcp::Caller::authenticated(account)))
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

/// Current hosted membership for the v1-compatible pseudonymous activity
/// relation. Its admission is independent of Person/content visibility.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn activity_members_on(
    conn: &mut SqliteConnection,
    viewer: &str,
) -> Result<BTreeMap<String, String>> {
    let roster = roster_on(conn)
        .await?
        .filter(|roster| roster.members.values().any(|id| id == viewer))
        .ok_or_else(|| Error::auth("activity requires current hosted membership"))?;
    Ok(roster.members.clone())
}

/// The reserved host bindings that bypass roster admission. `admitted`'s
/// SQL names exactly these (pinned by a test).
pub(crate) const HOST_ADMISSION_BINDINGS: [&str; 2] = [
    "host:v1-import",
    super::relates_to_port::HOST_TRANSFORM_BINDING,
];

/// The workspace admission fence's roster, selected in the caller's
/// snapshot: `None` when the workspace has no hosted roster (everyone is
/// admitted).
pub(crate) struct Admission(Option<Arc<Roster>>);

pub(crate) async fn admission_on(conn: &mut SqliteConnection) -> Result<Admission> {
    Ok(Admission(roster_on(conn).await?))
}

/// The admission rule shared by [`admitted`] and the stored-visibility
/// derivation: without a roster everyone is admitted; with one, a reserved
/// host binding or roster membership admits. Membership is a scan of the
/// roster, so its cost grows with the roster.
pub(crate) fn admitted_with(admission: &Admission, host_binding: bool, principal: &str) -> bool {
    match &admission.0 {
        None => true,
        Some(roster) => host_binding || roster.members.values().any(|id| id == principal),
    }
}

// Membership is a workspace-wide admission fence, before even owner floors.
// Reserved host services remain usable; they cannot be authenticated accounts.
pub(crate) async fn admitted(conn: &mut SqliteConnection, principal: &str) -> Result<bool> {
    let admission = admission_on(conn).await?;
    if admission.0.is_none() {
        return Ok(true);
    }
    let host: bool = sqlx::query_scalar(ADMITTED_HOST_SQL)
        .bind(principal)
        .fetch_one(conn)
        .await?;
    Ok(admitted_with(&admission, host, principal))
}

pub(crate) const ADMITTED_HOST_SQL: &str = "SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding IN ('host:v1-import','host:relates-to:transform'))";

/// Read a member's portable identity through the immutable H3 catalogue map
/// and current roster. The host already authorized catalogue roster disclosure;
/// this additional read must still respect the viewer's current Person View.
#[cfg(feature = "v2-kernel-probe")]
pub async fn visible_member_identity_as(
    db: &Db,
    viewer: &str,
    catalog_account: &str,
) -> Result<Option<(String, String)>> {
    let mut tx = db.pool().begin().await?;
    app_installs::admit_dispatched_on(&mut tx, viewer).await?;
    if !admitted(&mut tx, viewer).await? {
        return Err(Error::engine("database membership not found"));
    }
    let Some(roster) = roster_on(&mut tx).await? else {
        return Ok(None);
    };
    let principal = roster
        .catalog_accounts
        .get(catalog_account)
        .and_then(|binding| roster.members.get(binding));
    let Some(principal) = principal else {
        return Ok(None);
    };
    let person: Option<String> =
        sqlx::query_scalar("SELECT person_id FROM kernel_message_people WHERE principal_id=?")
            .bind(principal)
            .fetch_optional(&mut *tx)
            .await?;
    let result = if let Some(person) = person {
        read_record_on(&mut tx, viewer, &person)
            .await?
            .map(|record| (principal.clone(), record.id))
    } else {
        None
    };
    tx.rollback().await?;
    Ok(result)
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
pub async fn catalog_account_on(
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

/// Resolve only the authenticated host identity's retained account mapping.
/// This does NOT admit the account: former members retain their immutable
/// mapping so member-copy capture can return a verified purge instruction.
/// Serving still requires the current roster and kernel root View in the
/// same source transaction. Never expose this as a directory lookup.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn retained_catalog_account_on(
    conn: &mut SqliteConnection,
    authenticated_catalog_id: &str,
) -> Result<Option<String>> {
    Ok(roster_on(conn).await?.and_then(|roster| {
        roster
            .catalog_accounts
            .get(authenticated_catalog_id)
            .cloned()
    }))
}

/// The current caller's stored H3 aliases, never a workspace directory.
/// Catalogue ids differ from portable credentials after an imported cutover.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn catalog_identifiers_on(
    conn: &mut SqliteConnection,
    principal: &str,
    account: &str,
) -> Result<Vec<String>> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(vec![]);
    };
    if roster.members.get(account).map(String::as_str) != Some(principal) {
        return Ok(vec![]);
    }
    Ok(roster
        .catalog_accounts
        .iter()
        .filter(|(_, binding)| binding.as_str() == account)
        .map(|(catalog, _)| catalog.clone())
        .collect())
}

pub(super) type PolicyRows = Vec<(String, String, String, String)>;

pub(crate) async fn policy_rows(
    conn: &mut SqliteConnection,
    principal: &str,
    home: &str,
) -> Result<Option<Vec<(String, String, String, String)>>> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(None);
    };
    let Some(p) = current_member_policy_on(conn, home).await? else {
        return Ok(None);
    };
    Ok(Some(expand_policy_rows(&p, &roster, principal)))
}

fn expand_policy_rows(
    p: &MemberPolicy,
    roster: &Roster,
    principal: &str,
) -> Vec<(String, String, String, String)> {
    let mut rows: Vec<_> = p
        .explicit
        .iter()
        .map(|(id, cap)| ("account".into(), id.clone(), "allow".into(), cap.clone()))
        .collect();
    if roster.members.values().any(|id| id == principal) {
        if let Some(cap) = &p.members {
            rows.push((
                "account".into(),
                principal.into(),
                "allow".into(),
                cap.clone(),
            ));
        }
    }
    rows
}

/// Newest member-policy template event for each policy home. Drives from the
/// (few) policy homes and looks each one up by `record_id`. Joining from
/// `content_events` instead made SQLite scan every event in the workspace on
/// every bulk visibility read: about 460 ms of the ~510 ms fixed cost of each
/// v2 read on HQ (466k events). A home with no matching event yields NULL,
/// which `IN` never matches, so the selected set is unchanged.
pub(super) const POLICY_TEMPLATES_SQL: &str = "SELECT record_id,seq,type,payload FROM main.content_events WHERE seq IN (SELECT (SELECT max(e.seq) FROM main.content_events e WHERE e.record_id=p.root_id AND (e.type=?1 OR (e.type='kernel.home_policy_replaced.v1' AND json_type(e.payload,'$.record_policy')='object'))) FROM main.kernel_policies p)";

/// Newest home/policy frontier event for each policy home. Only policy homes
/// are consulted below (every template comes from `kernel_policies`), so this
/// is driven from those homes through `idx_kernel_hosted_event_lookup`
/// (record_id, type, seq) instead of grouping the whole event log, which cost
/// ~40 ms warm (~116 ms cold) on every bulk visibility read on HQ. Homes with
/// no frontier event are omitted, exactly as the grouped form omitted them.
pub(super) const POLICY_FRONTIERS_SQL: &str = "SELECT root_id, frontier FROM (SELECT p.root_id, (SELECT max(e.seq) FROM main.content_events e WHERE e.record_id=p.root_id AND e.type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')) AS frontier FROM main.kernel_policies p) WHERE frontier IS NOT NULL";

/// The same imported-policy override as `policy_rows`, loaded once for a bulk
/// home evaluation. All facts belong to the caller's existing snapshot; no
/// result survives the request or replaces the live roster/cleanup fences.
// The bulk census now supplies its own subjects
// (`policy_rows_bulk_with_subjects_on`); this whole-workspace form remains
// as the parity reference for that path.
#[cfg(test)]
pub(super) async fn policy_rows_bulk_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<BTreeMap<String, PolicyRows>> {
    Box::pin(policy_rows_loaded_on(conn, principal, None)).await
}

/// The same template, frontier and subject rules as `policy_rows_bulk_on`,
/// driven only from the named policy homes. Demand-scoped point reads use it
/// so their cost follows the path's anchors, not every policy home.
pub(super) const ANCHOR_POLICY_TEMPLATES_SQL: &str = "SELECT record_id,seq,type,payload FROM main.content_events WHERE seq IN (SELECT (SELECT max(e.seq) FROM main.content_events e WHERE e.record_id=p.root_id AND (e.type=?1 OR (e.type='kernel.home_policy_replaced.v1' AND json_type(e.payload,'$.record_policy')='object'))) FROM main.kernel_policies p WHERE p.root_id IN (SELECT value FROM json_each(?2)))";
pub(super) const ANCHOR_POLICY_FRONTIERS_SQL: &str = "SELECT root_id, frontier FROM (SELECT p.root_id, (SELECT max(e.seq) FROM main.content_events e WHERE e.record_id=p.root_id AND e.type IN ('kernel.import_home.v1','kernel.import_home_delta.v1','kernel.import_home_policy.v1','kernel.home_policy_replaced.v1')) AS frontier FROM main.kernel_policies p WHERE p.root_id IN (SELECT value FROM json_each(?1))) WHERE frontier IS NOT NULL";

/// Probe-gated demand-visibility point reads and default test builds
/// (stored-visibility scope tests) call this; default non-test builds
/// stamp no policy reads through anchors.
#[cfg(any(test, feature = "v2-kernel-probe"))]
pub(super) async fn policy_rows_for_anchors_on(
    conn: &mut SqliteConnection,
    principal: &str,
    anchors: &BTreeSet<String>,
) -> Result<BTreeMap<String, PolicyRows>> {
    Box::pin(policy_rows_loaded_on(conn, principal, Some(anchors))).await
}

/// The current hosted member-policy template of each loaded policy home,
/// under the hosted roster, all from one snapshot: the newest template, only
/// when its `policy_seq` equals the home's frontier, with explicit grants
/// kept only for the home's physical account subjects. A home without a
/// current template is absent: the anchor's own entries apply, which is not
/// a denial. Callers expand per principal with [`MemberPolicies::rows_for`].
pub(crate) struct MemberPolicies {
    roster: Arc<Roster>,
    current: BTreeMap<String, MemberPolicy>,
}

impl MemberPolicies {
    /// The hosted rows that **replace** `home`'s entries for `principal`, or
    /// `None` when `home` has no current template.
    pub(crate) fn rows_for(&self, home: &str, principal: &str) -> Option<PolicyRows> {
        self.current
            .get(home)
            .map(|p| expand_policy_rows(p, &self.roster, principal))
    }
}

/// The principal-independent half of the hosted policy override: roster,
/// templates, frontiers and physical subjects, for every policy home or only
/// `anchors`. `None` without a hosted roster. Its cost grows with the
/// homes' grants, template JSON and history, and with the roster (a
/// disclosed stored-visibility qualification item).
pub(crate) async fn load_member_policies_on(
    conn: &mut SqliteConnection,
    anchors: Option<&BTreeSet<String>>,
) -> Result<Option<MemberPolicies>> {
    Box::pin(load_member_policies_with_on(conn, anchors, None)).await
}

/// Physical account subjects per policy home: the `subject_kind =
/// 'account'` rows of `kernel_policy_entries`, as a set per `root_id`.
pub(super) type AccountSubjects = BTreeMap<String, BTreeSet<String>>;

/// [`load_member_policies_on`], optionally given the physical account
/// subjects. A caller that already read every `kernel_policy_entries` row in
/// this same snapshot (the bulk census) supplies them, so the table is not
/// read twice; they must cover the same homes the load does.
async fn load_member_policies_with_on(
    conn: &mut SqliteConnection,
    anchors: Option<&BTreeSet<String>>,
    known_subjects: Option<&AccountSubjects>,
) -> Result<Option<MemberPolicies>> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(None);
    };
    let anchor_json = anchors.map(serde_json::to_string).transpose()?;
    let templates: Vec<(String, i64, String, String)> = match &anchor_json {
        None => {
            sqlx::query_as(POLICY_TEMPLATES_SQL)
                .bind(POLICY_EVENT)
                .fetch_all(&mut *conn)
                .await?
        }
        Some(anchors) => {
            sqlx::query_as(ANCHOR_POLICY_TEMPLATES_SQL)
                .bind(POLICY_EVENT)
                .bind(anchors)
                .fetch_all(&mut *conn)
                .await?
        }
    };
    let frontiers: BTreeMap<String, i64> = match &anchor_json {
        None => {
            sqlx::query_as::<_, (String, i64)>(POLICY_FRONTIERS_SQL)
                .fetch_all(&mut *conn)
                .await?
        }
        Some(anchors) => {
            sqlx::query_as::<_, (String, i64)>(ANCHOR_POLICY_FRONTIERS_SQL)
                .bind(anchors)
                .fetch_all(&mut *conn)
                .await?
        }
    }
    .into_iter()
    .collect();
    let loaded;
    let subjects = match known_subjects {
        Some(subjects) => subjects,
        None => {
            let subject_rows: Vec<(String, String)> = match &anchor_json {
                None => sqlx::query_as(
                    "SELECT root_id,subject_id FROM main.kernel_policy_entries WHERE subject_kind='account'",
                )
                .fetch_all(&mut *conn)
                .await?,
                Some(anchors) => sqlx::query_as(
                    "SELECT root_id,subject_id FROM main.kernel_policy_entries WHERE subject_kind='account' AND root_id IN (SELECT value FROM json_each(?1))",
                )
                .bind(anchors)
                .fetch_all(&mut *conn)
                .await?,
            };
            let mut subjects = AccountSubjects::new();
            for (home, subject) in subject_rows {
                subjects.entry(home).or_default().insert(subject);
            }
            loaded = subjects;
            &loaded
        }
    };
    let mut result = BTreeMap::new();
    for (home, seq, event_type, raw) in templates {
        let Some(mut p) = template_from_event(seq, &event_type, &raw)? else {
            continue;
        };
        if p.policy_seq != frontiers.get(&home).copied().unwrap_or(0) {
            continue;
        }
        p.explicit
            .retain(|id, _| subjects.get(&home).is_some_and(|s| s.contains(id)));
        result.insert(home, p);
    }
    Ok(Some(MemberPolicies {
        roster,
        current: result,
    }))
}

async fn policy_rows_loaded_on(
    conn: &mut SqliteConnection,
    principal: &str,
    anchors: Option<&BTreeSet<String>>,
) -> Result<BTreeMap<String, PolicyRows>> {
    let Some(policies) = load_member_policies_on(conn, anchors).await? else {
        return Ok(BTreeMap::new());
    };
    Ok(expand_all(&policies, principal))
}

fn expand_all(policies: &MemberPolicies, principal: &str) -> BTreeMap<String, PolicyRows> {
    policies
        .current
        .keys()
        .map(|home| {
            let rows = policies
                .rows_for(home, principal)
                .expect("a loaded home has a current template");
            (home.clone(), rows)
        })
        .collect()
}

/// The whole-workspace hosted rows for the bulk census, which has already read
/// every physical `kernel_policy_entries` row in this snapshot: `subjects`
/// are that read's account subjects, so the loader does not read the table
/// again. Same template replacement, frontier equality, physical-subject
/// retention and caller expansion.
pub(super) async fn policy_rows_bulk_with_subjects_on(
    conn: &mut SqliteConnection,
    principal: &str,
    subjects: &AccountSubjects,
) -> Result<BTreeMap<String, PolicyRows>> {
    let Some(policies) = Box::pin(load_member_policies_with_on(conn, None, Some(subjects))).await?
    else {
        return Ok(BTreeMap::new());
    };
    Ok(expand_all(&policies, principal))
}

/// The loader exactly as it was before the split, kept as the parity
/// reference for the shared loader (test only).
#[cfg(test)]
pub(crate) async fn policy_rows_loaded_previous_for_test(
    conn: &mut SqliteConnection,
    principal: &str,
    anchors: Option<&BTreeSet<String>>,
) -> Result<BTreeMap<String, PolicyRows>> {
    let Some(roster) = roster_on(conn).await? else {
        return Ok(BTreeMap::new());
    };
    let anchor_json = anchors.map(serde_json::to_string).transpose()?;
    let templates: Vec<(String, i64, String, String)> = match &anchor_json {
        None => {
            sqlx::query_as(POLICY_TEMPLATES_SQL)
                .bind(POLICY_EVENT)
                .fetch_all(&mut *conn)
                .await?
        }
        Some(anchors) => {
            sqlx::query_as(ANCHOR_POLICY_TEMPLATES_SQL)
                .bind(POLICY_EVENT)
                .bind(anchors)
                .fetch_all(&mut *conn)
                .await?
        }
    };
    let frontiers: BTreeMap<String, i64> = match &anchor_json {
        None => {
            sqlx::query_as::<_, (String, i64)>(POLICY_FRONTIERS_SQL)
                .fetch_all(&mut *conn)
                .await?
        }
        Some(anchors) => {
            sqlx::query_as::<_, (String, i64)>(ANCHOR_POLICY_FRONTIERS_SQL)
                .bind(anchors)
                .fetch_all(&mut *conn)
                .await?
        }
    }
    .into_iter()
    .collect();
    let subject_rows: Vec<(String, String)> = match &anchor_json {
        None => sqlx::query_as(
            "SELECT root_id,subject_id FROM main.kernel_policy_entries WHERE subject_kind='account'",
        )
        .fetch_all(&mut *conn)
        .await?,
        Some(anchors) => sqlx::query_as(
            "SELECT root_id,subject_id FROM main.kernel_policy_entries WHERE subject_kind='account' AND root_id IN (SELECT value FROM json_each(?1))",
        )
        .bind(anchors)
        .fetch_all(&mut *conn)
        .await?,
    };
    let mut subjects: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (home, subject) in subject_rows {
        subjects.entry(home).or_default().insert(subject);
    }
    let mut result = BTreeMap::new();
    for (home, seq, event_type, raw) in templates {
        let Some(mut p) = template_from_event(seq, &event_type, &raw)? else {
            continue;
        };
        if p.policy_seq != frontiers.get(&home).copied().unwrap_or(0) {
            continue;
        }
        p.explicit
            .retain(|id, _| subjects.get(&home).is_some_and(|s| s.contains(id)));
        result.insert(home, expand_policy_rows(&p, &roster, principal));
    }
    Ok(result)
}

/// Source policy subjects, preserving members vs explicit-account grants.
/// Never infer account-only privacy from a one-member expanded roster.
#[cfg(feature = "v2-kernel-probe")]
pub(crate) async fn policy_description_on(
    conn: &mut SqliteConnection,
    home: &str,
) -> Result<Option<Vec<(String, String, String, String)>>> {
    let Some(p) = current_member_policy_on(conn, home).await? else {
        return Ok(None);
    };
    let mut rows: Vec<_> = p
        .explicit
        .into_iter()
        .map(|(id, cap)| ("account".into(), id, "allow".into(), cap))
        .collect();
    if let Some(cap) = p.members {
        rows.push(("members".into(), String::new(), "allow".into(), cap));
    }
    Ok(Some(rows))
}

async fn current_member_policy_on(
    conn: &mut SqliteConnection,
    home: &str,
) -> Result<Option<MemberPolicy>> {
    let raw: Option<(i64, String, String)> = sqlx::query_as(
        "SELECT seq,type,payload FROM main.content_events WHERE (type=? OR (type='kernel.home_policy_replaced.v1' AND json_type(payload,'$.record_policy')='object')) AND record_id=? AND seq<? ORDER BY seq DESC LIMIT 1",
    )
    .bind(POLICY_EVENT)
    .bind(home)
    .bind(read_before())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((template_seq, event_type, raw)) = raw else {
        return Ok(None);
    };
    let Some(mut p) = template_from_event(template_seq, &event_type, &raw)? else {
        return Ok(None);
    };
    if p.policy_seq != policy_seq_before(conn, home, read_before()).await? {
        return Ok(None);
    }
    // Cleanup deletes the physical account row. Keep import provenance only
    // while that row still exists: rejoin can restore the member baseline,
    // never a removed explicit grant. This also follows projection replay
    // order, unlike scanning future cleanup events from the immutable log.
    let subjects: BTreeSet<String> = sqlx::query_scalar("SELECT subject_id FROM main.kernel_policy_entries WHERE root_id=? AND subject_kind='account'")
        .bind(home).fetch_all(&mut *conn).await?.into_iter().collect();
    p.explicit.retain(|id, _| subjects.contains(id));
    Ok(Some(p))
}

pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    if event.event_type == offboarding::EVENT {
        return offboarding::project(conn, event).await;
    }
    if event.event_type == bundles::BUNDLE_DEFINED_EVENT
        || event.event_type == bundles::BUNDLE_UPDATED_EVENT
    {
        return bundles::project_bundle(conn, event).await;
    }
    if event.event_type == bundles::ROSTER_V2_EVENT {
        return bundles::project_roster_v2(conn, event).await;
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
        // Catalogue bindings stay immutable across roster versions: a v1/v2
        // transition must not rebind an account.
        let previous: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type IN (?,?) AND seq<? ORDER BY seq DESC LIMIT 1")
            .bind(KERNEL_ROOT_ID).bind(ROSTER_EVENT).bind(bundles::ROSTER_V2_EVENT).bind(event.local_seq).fetch_optional(&mut *conn).await?;
        if let Some(raw) = previous {
            // Both roster versions carry `catalog_accounts` under the same key.
            let old_accounts: BTreeMap<String, String> =
                serde_json::from_str::<serde_json::Value>(&raw)
                    .ok()
                    .and_then(|value| value.get("catalog_accounts").cloned())
                    .and_then(|accounts| serde_json::from_value(accounts).ok())
                    .ok_or_else(|| Error::engine("invalid hosted roster envelope"))?;
            if old_accounts
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

/// Test-only: roster parses and their time, for the S1a roster-size axis.
/// Parsing happens in Rust, outside SQLite's statement counters. It lives
/// beside the test module to satisfy clippy's items_after_test_module lint.
#[cfg(test)]
pub(crate) mod roster_parse_probe {
    use std::sync::atomic::{AtomicU64, Ordering};
    static PARSES: AtomicU64 = AtomicU64::new(0);
    static NANOS: AtomicU64 = AtomicU64::new(0);
    pub(super) fn record(elapsed: std::time::Duration) {
        PARSES.fetch_add(1, Ordering::Relaxed);
        NANOS.fetch_add(elapsed.as_nanos() as u64, Ordering::Relaxed);
    }
    /// (parses, nanoseconds) since the previous call. Only the
    /// probe-gated demand-visibility tests read it.
    #[cfg(feature = "v2-kernel-probe")]
    pub(crate) fn take() -> (u64, u64) {
        (
            PARSES.swap(0, Ordering::Relaxed),
            NANOS.swap(0, Ordering::Relaxed),
        )
    }
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
mod tests;
