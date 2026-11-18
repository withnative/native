//! Membership bundles: named, seeded permission sets stored as kernel events.
//!
//! Slice 2a stores only. Bundle definitions live in the kernel log on
//! `KERNEL_ROOT_ID`; nothing consumes them yet and behaviour does not change.
//! Reads fold the event log directly — the roster precedent — so this slice
//! adds no kernel table: the v2 owned schema and its generation coordinates
//! (`standby::kernel_v2::coordinates`, exact `sqlite_schema` match against
//! `create_v2_database`) are untouched. A current-state projection table, if
//! wanted later, is a pure accelerator over this same fold.
//!
//! Writers in this slice are host-only: creation-time seeding and the
//! idempotent `ensure_seeded_bundles` for existing databases. There is no
//! public write path; `store::reject_public_runtime_event` refuses all three
//! event types below from generic appends.
use super::*;

/// First definition of one membership bundle id.
pub(crate) const BUNDLE_DEFINED_EVENT: &str = "kernel.membership_bundle_defined.v1";
/// Full replacement of a previously defined bundle id.
pub(crate) const BUNDLE_UPDATED_EVENT: &str = "kernel.membership_bundle_updated.v1";
/// Roster carrying a bundle id per member. No writer emits it yet, and none
/// may until every v1-scoped roster fence moves with it. Admission
/// (`roster_on`/`roster_before`) deliberately still reads v1 only: a v2
/// member is not admitted by presence here, so a `guest` entry stays out
/// exactly as v1 keeps guests out. Before the first v2 writer, move ALL of:
///
/// - `hq::require_source_import_open` and the import-closed checks (hq.rs,
///   app_installs `IMPORT_CLOSED_INDEX`)
/// - the activation checks (hosted_identity `import_accounts` liveness,
///   `activated_on`, v1_import liveness, and the `held/` HTTP, v2 and
///   v2-cutover activation reads)
/// - the `kernel.import_hosted_accounts.v1` projection liveness check, which
///   is separate from `import_accounts`
/// - the admission-horizon fences (claims_port, relates_to_port)
/// - the effect-time fences (app_installs, artifact_closures, canvas_v2,
///   notifications incl. `REALTIME_AUTHORITY_INDEX`, workspace_snapshot)
/// - the writer itself (`reconcile_hosted_caller` still emits v1 only)
///
/// (The v1 roster projection's catalogue-immutability check already reads v1
/// and v2, with the same outcome while there are no v2 events.)
///
/// `roster_view_before` below is the only v1+v2 reader, and nothing in
/// admission or authorization may call it until then.
pub(crate) const ROSTER_V2_EVENT: &str = "kernel.hosted_membership.v2";

/// Seeded bundle ids. Owner, member and guest reproduce today's behaviour.
pub(crate) const OWNER_BUNDLE_ID: &str = "owner";
pub(crate) const MEMBER_BUNDLE_ID: &str = "member";
pub(crate) const GUEST_BUNDLE_ID: &str = "guest";

/// Version of the settings map shape. Bumped only if the envelope itself
/// changes; new setting keys round-trip as unknown `values` entries.
pub(crate) const BUNDLE_SETTINGS_VERSION: u32 = 1;

/// The nine settings of slice 2a, with their canonical string names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BundleSetting {
    MembersBaseline,
    Mcp,
    ExpiryRequired,
    PrivateAgentContext,
    SeeMemberList,
    CountsInAudience,
    OfflineCopy,
    ManageAccess,
    ManageWorkspace,
}

impl BundleSetting {
    pub fn all() -> [BundleSetting; 9] {
        [
            BundleSetting::MembersBaseline,
            BundleSetting::Mcp,
            BundleSetting::ExpiryRequired,
            BundleSetting::PrivateAgentContext,
            BundleSetting::SeeMemberList,
            BundleSetting::CountsInAudience,
            BundleSetting::OfflineCopy,
            BundleSetting::ManageAccess,
            BundleSetting::ManageWorkspace,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            BundleSetting::MembersBaseline => "members_baseline",
            BundleSetting::Mcp => "mcp",
            BundleSetting::ExpiryRequired => "expiry_required",
            BundleSetting::PrivateAgentContext => "private_agent_context",
            BundleSetting::SeeMemberList => "see_member_list",
            BundleSetting::CountsInAudience => "counts_in_audience",
            BundleSetting::OfflineCopy => "offline_copy",
            BundleSetting::ManageAccess => "manage_access",
            BundleSetting::ManageWorkspace => "manage_workspace",
        }
    }

    pub fn parse(value: &str) -> Option<BundleSetting> {
        BundleSetting::all()
            .into_iter()
            .find(|setting| setting.as_str() == value)
    }
}

/// Versioned map from setting name to value. Values stay `serde_json::Value`
/// so unknown future keys round-trip through readers that predate them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleSettings {
    pub version: u32,
    pub values: BTreeMap<String, serde_json::Value>,
}

/// One bundle definition. `defined` establishes an id; `updated` carries a
/// full replacement under the same shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleDefinition {
    pub id: String,
    pub name: String,
    pub description: String,
    pub seeded: bool,
    pub settings: BundleSettings,
}

impl BundleDefinition {
    /// Typed read of one boolean setting. `None` when the bundle does not
    /// carry the setting, or carries a non-boolean value for it.
    pub fn setting(&self, setting: BundleSetting) -> Option<bool> {
        self.settings
            .values
            .get(setting.as_str())
            .and_then(serde_json::Value::as_bool)
    }
}

fn seeded_values(all_true_except: &[BundleSetting], only: Option<BundleSetting>) -> BundleSettings {
    let mut values = BTreeMap::new();
    for setting in BundleSetting::all() {
        let value = match only {
            Some(wanted) => setting == wanted,
            None => !all_true_except.contains(&setting),
        };
        values.insert(setting.as_str().to_string(), serde_json::Value::Bool(value));
    }
    BundleSettings {
        version: BUNDLE_SETTINGS_VERSION,
        values,
    }
}

/// The seeded definition for `owner`, `member` or `guest`; `None` for any
/// other id. Owner is everything except `expiry_required`; member additionally
/// lacks `manage_access` and `manage_workspace`; guest carries only
/// `expiry_required`.
pub(crate) fn seeded_bundle(id: &str) -> Option<BundleDefinition> {
    let (name, description, settings) = match id {
        OWNER_BUNDLE_ID => (
            "Owner",
            "Full workspace access, including access and workspace administration.",
            seeded_values(&[BundleSetting::ExpiryRequired], None),
        ),
        MEMBER_BUNDLE_ID => (
            "Member",
            "Workspace membership without access or workspace administration.",
            seeded_values(
                &[
                    BundleSetting::ExpiryRequired,
                    BundleSetting::ManageAccess,
                    BundleSetting::ManageWorkspace,
                ],
                None,
            ),
        ),
        GUEST_BUNDLE_ID => (
            "Guest",
            "Limited access; an expiry is always required.",
            seeded_values(&[], Some(BundleSetting::ExpiryRequired)),
        ),
        _ => return None,
    };
    Some(BundleDefinition {
        id: id.to_string(),
        name: name.to_string(),
        description: description.to_string(),
        seeded: true,
        settings,
    })
}

pub(crate) fn validate_definition(definition: &BundleDefinition) -> Result<()> {
    if definition.id.trim().is_empty() || definition.id.len() > 64 {
        return Err(Error::engine("invalid membership bundle id"));
    }
    if definition.name.trim().is_empty() || definition.description.trim().is_empty() {
        return Err(Error::engine(
            "invalid membership bundle name or description",
        ));
    }
    if definition.settings.version != BUNDLE_SETTINGS_VERSION {
        return Err(Error::engine(
            "unsupported membership bundle settings version",
        ));
    }
    if definition
        .settings
        .values
        .keys()
        .any(|key| key.trim().is_empty())
    {
        return Err(Error::engine("invalid membership bundle setting name"));
    }
    Ok(())
}

/// Latest definition event (`defined` or `updated`) for one bundle id with
/// `seq < before`. Both event types share the `BundleDefinition` shape, so
/// the fold is simply the latest envelope.
pub(crate) async fn bundle_before(
    conn: &mut SqliteConnection,
    id: &str,
    before: i64,
) -> Result<Option<BundleDefinition>> {
    let raw: Option<String> = sqlx::query_scalar(
        "SELECT payload FROM main.content_events WHERE record_id=? AND type IN (?,?) AND seq<? AND json_extract(payload,'$.id')=? ORDER BY seq DESC LIMIT 1",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(BUNDLE_DEFINED_EVENT)
    .bind(BUNDLE_UPDATED_EVENT)
    .bind(before)
    .bind(id)
    .fetch_optional(conn)
    .await?;
    raw.map(|payload| {
        serde_json::from_str::<BundleDefinition>(&payload)
            .map_err(|_| Error::engine("invalid membership bundle envelope"))
    })
    .transpose()
}

/// Every bundle id with any definition event, each at its latest definition.
/// Ordered by id; unknown setting keys are preserved untouched.
pub(crate) async fn list_membership_bundles_before(
    conn: &mut SqliteConnection,
    before: i64,
) -> Result<Vec<BundleDefinition>> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT json_extract(payload,'$.id') FROM main.content_events WHERE record_id=? AND type IN (?,?) AND seq<? ORDER BY 1",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(BUNDLE_DEFINED_EVENT)
    .bind(BUNDLE_UPDATED_EVENT)
    .bind(before)
    .fetch_all(&mut *conn)
    .await?;
    let mut bundles = Vec::with_capacity(ids.len());
    for id in ids {
        if let Some(definition) = bundle_before(&mut *conn, &id, before).await? {
            bundles.push(definition);
        }
    }
    Ok(bundles)
}

/// Current bundle definitions as seen by ordinary kernel reads.
pub(crate) async fn list_membership_bundles_on(
    conn: &mut SqliteConnection,
) -> Result<Vec<BundleDefinition>> {
    list_membership_bundles_before(conn, super::read_before()).await
}

/// Append one bundle event through the host-only route. The projector
/// re-validates actor, target and envelope, including defined-once ordering.
pub(crate) async fn append_bundle_event_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    event_type: &str,
    definition: &BundleDefinition,
    actor: &str,
    acts: &mut crate::act::ActAllocation,
) -> Result<()> {
    if event_type != BUNDLE_DEFINED_EVENT && event_type != BUNDLE_UPDATED_EVENT {
        return Err(Error::engine("invalid membership bundle event"));
    }
    append_in(
        db,
        &mut *tx,
        AppendSpec {
            record_id: KERNEL_ROOT_ID.into(),
            event_type: event_type.into(),
            payload: serde_json::to_value(definition)?,
            actor: Some(actor.into()),
        },
        acts,
    )
    .await?;
    Ok(())
}

/// Define every seeded bundle missing from the log. Idempotent: existing
/// definitions (even later updated ones) are left alone.
pub(crate) async fn seed_bundles_in(
    db: &Db,
    tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
    host: &str,
    acts: &mut crate::act::ActAllocation,
) -> Result<()> {
    for id in [OWNER_BUNDLE_ID, MEMBER_BUNDLE_ID, GUEST_BUNDLE_ID] {
        let defined: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM main.content_events WHERE record_id=? AND type=? AND json_extract(payload,'$.id')=?)",
        )
        .bind(KERNEL_ROOT_ID)
        .bind(BUNDLE_DEFINED_EVENT)
        .bind(id)
        .fetch_one(&mut **tx)
        .await?;
        if !defined {
            let definition = seeded_bundle(id)
                .ok_or_else(|| Error::engine("unknown seeded membership bundle"))?;
            append_bundle_event_in(db, &mut *tx, BUNDLE_DEFINED_EVENT, &definition, host, acts)
                .await?;
        }
    }
    Ok(())
}

/// Seed a live database whose creation predates bundle seeding. Called by the
/// host, not by serving; safe to repeat.
pub(crate) async fn ensure_seeded_bundles(db: &Db) -> Result<()> {
    let mut tx = begin_write(db.write_pool()).await?;
    let host: String =
        sqlx::query_scalar("SELECT principal_id FROM main.kernel_principals WHERE auth_binding=?")
            .bind(hq::HOST_IMPORT_BINDING)
            .fetch_one(&mut *tx)
            .await?;
    let mut acts = crate::act::ActAllocation::new();
    seed_bundles_in(db, &mut tx, &host, &mut acts).await?;
    tx.commit().await?;
    Ok(())
}

/// `kernel.hosted_membership.v2` member entry: principal plus bundle id.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterMemberV2 {
    principal: String,
    bundle: String,
}

/// `kernel.hosted_membership.v2` payload. `catalog_accounts` keeps the v1
/// meaning and immutability rules.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RosterV2 {
    members: BTreeMap<String, RosterMemberV2>,
    catalog_accounts: BTreeMap<String, String>,
}

/// One roster member with its bundle id. `bundle` is `None` for members read
/// from a v1 event, which stores no bundle; a later slice maps that to
/// today's role.
#[derive(Clone, Debug)]
pub(crate) struct RosterMemberView {
    pub principal: String,
    pub bundle: Option<String>,
}

/// Roster state across both event versions: the latest of v1/v2 by `seq`.
#[derive(Clone, Debug, Default)]
pub(crate) struct RosterView {
    pub members: BTreeMap<String, RosterMemberView>,
    pub catalog_accounts: BTreeMap<String, String>,
}

pub(crate) fn parse_roster_view(event_type: &str, payload: &str) -> Result<RosterView> {
    if event_type == super::ROSTER_EVENT {
        let roster: super::Roster = serde_json::from_str(payload)
            .map_err(|_| Error::engine("invalid hosted roster envelope"))?;
        return Ok(RosterView {
            members: roster
                .members
                .into_iter()
                .map(|(binding, principal)| {
                    (
                        binding,
                        RosterMemberView {
                            principal,
                            bundle: None,
                        },
                    )
                })
                .collect(),
            catalog_accounts: roster.catalog_accounts,
        });
    }
    if event_type == ROSTER_V2_EVENT {
        let roster: RosterV2 = serde_json::from_str(payload)
            .map_err(|_| Error::engine("invalid hosted roster envelope"))?;
        return Ok(RosterView {
            members: roster
                .members
                .into_iter()
                .map(|(binding, member)| {
                    (
                        binding,
                        RosterMemberView {
                            principal: member.principal,
                            bundle: Some(member.bundle),
                        },
                    )
                })
                .collect(),
            catalog_accounts: roster.catalog_accounts,
        });
    }
    Err(Error::engine("unknown hosted roster event"))
}

tokio::task_local! {
    static REQUEST_ROSTER_VIEWS: RefCell<HashMap<String, Arc<RosterView>>>;
}

#[cfg(all(test, feature = "v2-kernel-probe"))]
tokio::task_local! {
    static REFUSED_BUNDLE_ID: RefCell<Option<String>>;
}

/// Scope one bundle-projection refusal to the wrapped future. Test-only:
/// while scoped, the bundle projector refuses the named bundle id *after*
/// the event row is inserted (the production insert-before-project order),
/// so tests can prove a refused seed leaves nothing behind.
#[cfg(all(test, feature = "v2-kernel-probe"))]
pub(crate) async fn with_refused_bundle_id<F: Future>(id: &str, future: F) -> F::Output {
    REFUSED_BUNDLE_ID
        .scope(RefCell::new(Some(id.to_string())), future)
        .await
}

/// Latest roster event (v1 or v2) as a unified view. v1 members carry
/// `bundle: None`. Reads only: nothing in admission or authorization may call
/// this until the preconditions on `ROSTER_V2_EVENT` are met; the first v2
/// writer must move them first.
pub(crate) async fn roster_view_before(
    conn: &mut SqliteConnection,
    before: i64,
) -> Result<Option<(String, Arc<RosterView>)>> {
    let row: Option<(String, String, String)> = sqlx::query_as(
        "SELECT id,type,payload FROM main.content_events WHERE record_id=? AND type IN (?,?) AND seq<? ORDER BY seq DESC LIMIT 1",
    )
    .bind(KERNEL_ROOT_ID)
    .bind(super::ROSTER_EVENT)
    .bind(ROSTER_V2_EVENT)
    .bind(before)
    .fetch_optional(conn)
    .await?;
    let Some((id, event_type, raw)) = row else {
        return Ok(None);
    };
    if let Some(cached) = REQUEST_ROSTER_VIEWS
        .try_with(|c| c.borrow().get(&id).cloned())
        .ok()
        .flatten()
    {
        return Ok(Some((id, cached)));
    }
    let parsed = Arc::new(parse_roster_view(&event_type, &raw)?);
    let _ = REQUEST_ROSTER_VIEWS.try_with(|c| c.borrow_mut().insert(id.clone(), parsed.clone()));
    Ok(Some((id, parsed)))
}

/// Scope bundle/roster view reads to one request, mirroring `scope_request`.
pub(crate) async fn scope_view_request<F: Future>(future: F) -> F::Output {
    if REQUEST_ROSTER_VIEWS.try_with(|_| ()).is_ok() {
        future.await
    } else {
        REQUEST_ROSTER_VIEWS
            .scope(RefCell::new(HashMap::new()), future)
            .await
    }
}

/// Validate one bundle definition event. `defined` refuses when the id is
/// taken; `updated` requires a prior `defined` for the same id and must not
/// change the `seeded` flag (renaming is fine).
pub(crate) async fn project_bundle(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    hq::require_import(conn, event.actor.as_deref().unwrap_or_default()).await?;
    if event.record_id != KERNEL_ROOT_ID {
        return Err(Error::engine("invalid membership bundle target"));
    }
    let definition: BundleDefinition = event_payload(event)?;
    #[cfg(all(test, feature = "v2-kernel-probe"))]
    if REFUSED_BUNDLE_ID
        .try_with(|id| id.borrow().as_deref() == Some(definition.id.as_str()))
        .unwrap_or(false)
    {
        return Err(Error::engine("test-injected bundle projection refusal"));
    }
    validate_definition(&definition)?;
    let prior_defined: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type=? AND seq<? AND json_extract(payload,'$.id')=? ORDER BY seq DESC LIMIT 1")
        .bind(KERNEL_ROOT_ID).bind(BUNDLE_DEFINED_EVENT).bind(event.local_seq).bind(&definition.id).fetch_optional(&mut *conn).await?;
    if event.event_type == BUNDLE_DEFINED_EVENT {
        if prior_defined.is_some() {
            return Err(Error::engine("membership bundle is already defined"));
        }
        return Ok(());
    }
    let Some(prior) = prior_defined else {
        return Err(Error::engine(
            "membership bundle update names an undefined bundle",
        ));
    };
    // Fail closed: an unreadable prior definition refuses the update rather
    // than guessing at its seeded flag.
    let prior: BundleDefinition = serde_json::from_str(&prior)
        .map_err(|_| Error::engine("invalid membership bundle envelope"))?;
    if prior.seeded != definition.seeded {
        return Err(Error::engine(
            "membership bundle update cannot change the seeded flag",
        ));
    }
    Ok(())
}

/// Validate one v2 roster event. Shape rules mirror v1; the bundle id is
/// opaque here (a later slice resolves it) but must be non-blank.
pub(crate) async fn project_roster_v2(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if event.record_id != KERNEL_ROOT_ID {
        return Err(Error::engine("invalid hosted roster target"));
    }
    let roster: RosterV2 = event_payload(event)?;
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
    {
        return Err(Error::engine("invalid catalogue account mapping"));
    }
    let previous: Option<String> = sqlx::query_scalar("SELECT payload FROM main.content_events WHERE record_id=? AND type IN (?,?) AND seq<? ORDER BY seq DESC LIMIT 1")
        .bind(KERNEL_ROOT_ID).bind(super::ROSTER_EVENT).bind(ROSTER_V2_EVENT).bind(event.local_seq).fetch_optional(&mut *conn).await?;
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
            .any(|(id, account)| roster.catalog_accounts.get(id) != Some(account))
        {
            return Err(Error::engine("catalogue account bindings are immutable"));
        }
    }
    for (binding, member) in &roster.members {
        if member.bundle.trim().is_empty() || binding.starts_with("host:") {
            return Err(Error::engine("invalid hosted roster binding"));
        }
        let valid: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.kernel_principals WHERE principal_id=? AND auth_binding=? AND kind='account')")
            .bind(&member.principal).bind(binding).fetch_one(&mut *conn).await?;
        if !valid {
            return Err(Error::engine("invalid hosted roster binding"));
        }
    }
    Ok(())
}
