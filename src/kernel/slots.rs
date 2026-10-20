//! Host slot map storage (Foci v2 G7): two projection tables, two sealed
//! content-log events, their fold, and the compiled-in slot registry. The
//! evaluator, receipts and gate live in `slots_eval`; the operations and
//! provisioner arrive in later increments.
//!
//! A slot maps `(principal, slot) -> target`. v2 has no `control_events`
//! table, so registration is a pair of sealed content events folded on
//! replay. Only the sealed route (`store::append_kernel_slot_in`) can append
//! them; every generic, public and import seam refuses them.
use super::*;

pub(super) const SLOTS_DDL: &str = "CREATE TABLE kernel_slots (principal_id TEXT NOT NULL REFERENCES kernel_principals(principal_id), slot TEXT NOT NULL, target_id TEXT NOT NULL, generation INTEGER NOT NULL CHECK (generation >= 1), set_seq INTEGER NOT NULL CHECK (set_seq >= 1), PRIMARY KEY (principal_id, slot))";
/// Every target a slot has ever held. `UNIQUE(target_id)` registers a target
/// once, ever; `UNIQUE(principal_id, slot, previous_target_id)` is the
/// rebound key a retried replace looks up. NULLs are distinct in SQLite, so
/// first registrations (no previous target) do not collide.
pub(super) const LINEAGE_DDL: &str = "CREATE TABLE kernel_slot_lineage (principal_id TEXT NOT NULL, slot TEXT NOT NULL, generation INTEGER NOT NULL CHECK (generation >= 1), target_id TEXT NOT NULL UNIQUE, previous_target_id TEXT, event_seq INTEGER NOT NULL, PRIMARY KEY (principal_id, slot, generation), UNIQUE (principal_id, slot, previous_target_id))";
/// Lets the recovery fence seek one earlier home's owner-matching rows.
pub(super) const HOME_OWNER_INDEX_DDL: &str =
    "CREATE INDEX idx_kernel_records_home_owner ON kernel_records(home_id, owner_id)";

pub(crate) const PROVISIONED: &str = "kernel.slot_provisioned.v1";
pub(crate) const REPLACED: &str = "kernel.slot_replaced.v1";
/// A home created for a beneficiary by a provisioning service (Foci v2 G6,
/// design 681a449 §3.3). It rides the sealed slot route but registers nothing:
/// the slot event that follows in the same act does that.
pub(crate) const HOME_CREATED_FOR: &str = "kernel.home_created_for.v1";

pub(crate) const HOME_FOCI_PRIVATE: &str = "home:foci_private";
pub(crate) const RECORD_FOCI_PREFERENCES: &str = "record:native.foci.preferences/focus_preferences";

pub(crate) fn is_slot_event(event_type: &str) -> bool {
    matches!(event_type, PROVISIONED | REPLACED | HOME_CREATED_FOR)
}

/// Which table a slot's target lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SlotKind {
    Home,
    Record,
}

/// What a record slot's target must be: its pin family and kind, and the home
/// slot whose current target it must sit in.
pub(crate) struct RecordTarget {
    pub family: &'static str,
    pub kind: &'static str,
    pub home_slot: &'static str,
}

/// One entry of the compiled-in registry. Slot names are append-only: once an
/// event names a slot, later binaries must keep recognising it.
pub(crate) struct SlotSpec {
    pub name: &'static str,
    pub kind: SlotKind,
    /// Record slots only: the structure a valid target has.
    pub record: Option<RecordTarget>,
    /// Home slots only: the pin families the recovery fence looks for in the
    /// slot's earlier homes.
    pub holds: &'static [&'static str],
}

/// The compiled-in registry (Decision 1: adding a slot is a reviewed code
/// change, not a package declaration).
static REGISTRY: [SlotSpec; 2] = [
    SlotSpec {
        name: HOME_FOCI_PRIVATE,
        kind: SlotKind::Home,
        record: None,
        holds: &[
            crate::v2_standard::foci::FOCUS_FAMILY,
            crate::v2_standard::foci::SAVED_VIEW_FAMILY,
            crate::v2_standard::foci::PREFERENCES_FAMILY,
        ],
    },
    SlotSpec {
        name: RECORD_FOCI_PREFERENCES,
        kind: SlotKind::Record,
        record: Some(RecordTarget {
            family: crate::v2_standard::foci::PREFERENCES_FAMILY,
            kind: "focus_preferences",
            home_slot: HOME_FOCI_PRIVATE,
        }),
        holds: &[],
    },
];

pub(crate) fn slot_spec(slot: &str) -> Option<&'static SlotSpec> {
    REGISTRY.iter().find(|spec| spec.name == slot)
}

pub(crate) fn slot_kind(slot: &str) -> Option<SlotKind> {
    slot_spec(slot).map(|spec| spec.kind)
}

/// Canonical lowercase UUID, version 4 or 7, RFC 4122 variant.
pub(crate) fn valid_slot_id(id: &str) -> bool {
    match Uuid::parse_str(id) {
        Ok(uuid) => {
            uuid.hyphenated().to_string() == id
                && matches!(uuid.get_version_num(), 4 | 7)
                && uuid.get_variant() == uuid::Variant::RFC4122
        }
        Err(_) => false,
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisionedPayload {
    slot: String,
    target_id: String,
    reason: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplacedPayload {
    slot: String,
    previous_target_id: String,
    target_id: String,
    reason: String,
}

/// A slot event checked for shape and for who may have written it. Shared by
/// admission (before the append) and the fold, so the two cannot disagree.
struct Registration {
    principal: String,
    slot: String,
    kind: SlotKind,
    target_id: String,
    previous_target_id: Option<String>,
}

/// Where a registration lands in the lineage: the generation it takes.
struct Placement {
    generation: i64,
}

async fn decode(conn: &mut SqliteConnection, event: &EventRow) -> Result<Registration> {
    let (slot, target_id, previous_target_id, reason) = match event.event_type.as_str() {
        PROVISIONED => {
            let p: ProvisionedPayload = event_payload(event)?;
            (p.slot, p.target_id, None, p.reason)
        }
        REPLACED => {
            let p: ReplacedPayload = event_payload(event)?;
            (p.slot, p.target_id, Some(p.previous_target_id), p.reason)
        }
        _ => return Err(Error::engine("unknown slot event")),
    };
    if reason.trim().is_empty() {
        return Err(Error::engine("slot event reason must not be blank"));
    }
    let kind = slot_kind(&slot).ok_or_else(|| Error::engine("unknown slot"))?;
    if !valid_slot_id(&target_id) || !previous_target_id.as_deref().is_none_or(valid_slot_id) {
        return Err(Error::engine("invalid slot target id"));
    }
    if previous_target_id.as_deref() == Some(target_id.as_str()) {
        return Err(Error::engine("slot replacement must change the target"));
    }
    let principal = event.record_id.clone();
    if event.actor.as_deref() != Some(principal.as_str()) {
        return Err(Error::engine("slot event actor must be the slot principal"));
    }
    let principal_kind: Option<String> =
        sqlx::query_scalar("SELECT kind FROM kernel_principals WHERE principal_id=?")
            .bind(&principal)
            .fetch_optional(&mut *conn)
            .await?;
    if principal_kind.as_deref() != Some("account") {
        return Err(Error::engine("slot principal must be an account"));
    }
    Ok(Registration {
        principal,
        slot,
        kind,
        target_id,
        previous_target_id,
    })
}

/// The lineage checks, shared by admission and the fold: the target exists in
/// the table the slot's type names, has never been registered, and the event
/// continues the slot's current row. An inconsistent lineage is a hard error.
async fn check_lineage(conn: &mut SqliteConnection, r: &Registration) -> Result<Placement> {
    let target_exists: bool = match r.kind {
        SlotKind::Home => sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=? AND root_id<>?)",
        )
        .bind(&r.target_id)
        .bind(KERNEL_ROOT_ID),
        SlotKind::Record => {
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_records WHERE id=?)")
                .bind(&r.target_id)
        }
    }
    .fetch_one(&mut *conn)
    .await?;
    if !target_exists {
        return Err(Error::engine("slot target does not exist"));
    }
    let registered: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_slot_lineage WHERE target_id=?)")
            .bind(&r.target_id)
            .fetch_one(&mut *conn)
            .await?;
    if registered {
        return Err(Error::engine("slot target is already registered"));
    }
    let current: Option<(String, i64)> = sqlx::query_as(
        "SELECT target_id, generation FROM kernel_slots WHERE principal_id=? AND slot=?",
    )
    .bind(&r.principal)
    .bind(&r.slot)
    .fetch_optional(&mut *conn)
    .await?;
    let generation = match (&r.previous_target_id, current) {
        (None, None) => 1,
        (None, Some(_)) => return Err(Error::engine("slot is already provisioned")),
        (Some(_), None) => return Err(Error::engine("slot replacement has no current target")),
        (Some(previous), Some((current_target, generation))) => {
            if *previous != current_target {
                return Err(Error::engine(
                    "slot replacement does not match the current target",
                ));
            }
            generation + 1
        }
    };
    Ok(Placement { generation })
}

/// Sealed admission, run before the append for every admission route. Other
/// event types pass through. A slot event is admitted when its shape and
/// lineage hold and its target satisfies the slot's **structure** predicate
/// in this transaction (design §3.2, §6.2). Admission checks structure, never
/// recovery debt: a replacement home necessarily starts with debt, and
/// readiness is for ordinary use, not for registration. A record slot also
/// needs its home ready, because the record must sit in a home that ordinary
/// use will accept.
pub(crate) async fn admit(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    if !is_slot_event(&event.event_type) {
        return Ok(());
    }
    if event.event_type == HOME_CREATED_FOR {
        return admit_home_for(conn, event).await;
    }
    let r = decode(conn, event).await?;
    check_lineage(conn, &r).await?;
    super::slots_eval::admit_structure_on(conn, &r.principal, &r.slot, &r.target_id).await
}

/// The fold. It checks lineage only, never today's policy, content or debt:
/// ownership and privacy were admitted at append time and may legitimately
/// change later. An inconsistent lineage is a hard error, so a rebuild fails
/// rather than skipping it.
pub(crate) async fn project(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let logged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM content_events WHERE seq=? AND id=? AND record_id=? AND type=? AND actor IS ? AND payload IS ? AND created_at=?)")
        .bind(event.local_seq).bind(&event.id).bind(&event.record_id).bind(&event.event_type).bind(&event.actor).bind(&event.payload).bind(&event.created_at).fetch_one(&mut *conn).await?;
    if !logged {
        return Err(Error::engine(
            "slot projection requires the kernel-issued logged event",
        ));
    }
    if event.event_type == HOME_CREATED_FOR {
        return project_home_for(conn, event).await;
    }
    let r = decode(conn, event).await?;
    let Placement { generation } = check_lineage(conn, &r).await?;
    sqlx::query("INSERT INTO kernel_slot_lineage(principal_id,slot,generation,target_id,previous_target_id,event_seq) VALUES(?,?,?,?,?,?)")
        .bind(&r.principal).bind(&r.slot).bind(generation).bind(&r.target_id).bind(&r.previous_target_id).bind(event.local_seq)
        .execute(&mut *conn).await?;
    sqlx::query("INSERT INTO kernel_slots(principal_id,slot,target_id,generation,set_seq) VALUES(?,?,?,?,?) ON CONFLICT(principal_id,slot) DO UPDATE SET target_id=excluded.target_id,generation=excluded.generation,set_seq=excluded.set_seq")
        .bind(&r.principal).bind(&r.slot).bind(&r.target_id).bind(generation).bind(event.local_seq)
        .execute(&mut *conn).await?;
    Ok(())
}

/// The one writer of slot events. Appends through the sealed route in the
/// caller's transaction, after the target's own creation event and with the
/// same act allocation. `previous_target_id` `None` provisions; `Some`
/// replaces. The event's actor is the principal it registers for.
#[allow(dead_code, clippy::too_many_arguments)] // Operations arrive in later increments; the fixtures use it now.
pub(crate) async fn append_registration_in(
    db: &Db,
    tx: &mut Transaction<'static, Sqlite>,
    acts: &mut crate::act::ActAllocation,
    principal: &str,
    slot: &str,
    target_id: &str,
    previous_target_id: Option<&str>,
    reason: &str,
) -> Result<EventRow> {
    let (event_type, payload) = match previous_target_id {
        None => (
            PROVISIONED,
            serde_json::to_value(ProvisionedPayload {
                slot: slot.into(),
                target_id: target_id.into(),
                reason: reason.into(),
            })?,
        ),
        Some(previous) => (
            REPLACED,
            serde_json::to_value(ReplacedPayload {
                slot: slot.into(),
                previous_target_id: previous.into(),
                target_id: target_id.into(),
                reason: reason.into(),
            })?,
        ),
    };
    crate::store::append_kernel_slot_in(
        db,
        tx,
        AppendSpec {
            record_id: principal.into(),
            event_type: event_type.into(),
            payload,
            actor: Some(principal.into()),
        },
        acts,
    )
    .await
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HomeCreatedForPayload {
    parent_id: String,
    owner_id: String,
    slot: String,
}

/// A `home_created_for` event checked for the rules that do not depend on the
/// provisioner's configuration. Shared by admission and the fold. Capability
/// is not among them: it is checked at admission only, because it may
/// legitimately change after the event is logged.
struct HomeFor {
    parent: String,
    owner: String,
}

async fn decode_home_for(conn: &mut SqliteConnection, event: &EventRow) -> Result<HomeFor> {
    let p: HomeCreatedForPayload = event_payload(event)?;
    if !valid_slot_id(&event.record_id) {
        return Err(Error::engine("home id is not a canonical id"));
    }
    if slot_kind(&p.slot) != Some(SlotKind::Home) {
        return Err(Error::engine("home slot is not a registered home slot"));
    }
    // The id spaces stay disjoint (design §4.2): a fresh home id is neither
    // an existing home nor an existing record.
    let taken: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?) OR EXISTS(SELECT 1 FROM kernel_records WHERE id=?)",
    )
    .bind(&event.record_id)
    .bind(&event.record_id)
    .fetch_one(&mut *conn)
    .await?;
    if taken {
        return Err(Error::engine("home id is not fresh"));
    }
    let actor = event
        .actor
        .as_deref()
        .ok_or_else(|| Error::engine("home creation requires an actor"))?;
    if principal_kind(conn, actor).await?.as_deref() != Some("agent") {
        return Err(Error::engine("home creation actor must be an agent"));
    }
    if p.parent_id == KERNEL_ROOT_ID {
        return Err(Error::engine("home creation parent must not be the root"));
    }
    let parent_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
            .bind(&p.parent_id)
            .fetch_one(&mut *conn)
            .await?;
    if !parent_exists {
        return Err(Error::engine("home creation parent is not a home"));
    }
    if p.owner_id == actor {
        return Err(Error::engine("home owner must not be the creating actor"));
    }
    if principal_kind(conn, &p.owner_id).await?.as_deref() != Some("account") {
        return Err(Error::engine("home owner must be an account"));
    }
    Ok(HomeFor {
        parent: p.parent_id,
        owner: p.owner_id,
    })
}

async fn principal_kind(conn: &mut SqliteConnection, principal: &str) -> Result<Option<String>> {
    Ok(
        sqlx::query_scalar("SELECT kind FROM kernel_principals WHERE principal_id=?")
            .bind(principal)
            .fetch_optional(&mut *conn)
            .await?,
    )
}

/// Capability-based, not configuration-based: any `agent` with Manage on a
/// non-root parent passes (design §3.3, fixture 74). The configured service
/// and parent are enforced by the sole appender, which builds the event.
async fn admit_home_for(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let h = decode_home_for(conn, event).await?;
    let actor = event.actor.as_deref().unwrap_or_default();
    let capability = super::slots_eval::capability_on(conn, actor, &h.parent).await?;
    if !capability.allows(Capability::Manage) {
        return Err(Error::engine(
            "home creation actor lacks Manage on the parent",
        ));
    }
    Ok(())
}

/// The fold fixes the policy: the owner is the payload owner and the home
/// carries exactly one own entry, allow-Manage for that owner. The service
/// and the admin end with no access.
async fn project_home_for(conn: &mut SqliteConnection, event: &EventRow) -> Result<()> {
    let h = decode_home_for(conn, event).await?;
    sqlx::query("INSERT INTO kernel_roots (root_id, parent_id, owner_id, created_seq, created_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&event.record_id).bind(&h.parent).bind(&h.owner).bind(event.local_seq).bind(&event.created_at)
        .execute(&mut *conn).await?;
    sqlx::query("INSERT INTO kernel_policies (root_id, created_at) VALUES (?, ?)")
        .bind(&event.record_id)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    sqlx::query("INSERT INTO kernel_policy_entries (root_id, subject_kind, subject_id, effect, capability) VALUES (?, 'account', ?, 'allow', 'manage')")
        .bind(&event.record_id).bind(&h.owner)
        .execute(&mut *conn).await?;
    Ok(())
}

/// The designated service and parent, held by the host as constructor state
/// (design §3.2). Never a request field.
#[allow(dead_code)] // The host wiring that holds it is increment 4.
#[derive(Debug, Clone)]
pub(crate) struct ProvisionerConfig {
    pub service: String,
    pub parent: String,
}

/// A configuration checked in one transaction. It holds the exclusive borrow
/// of that transaction, so nothing else can run on it between the check and
/// the append, and the appender consumes it, so one check authorises one
/// event. Only `ProvisionerConfig::validate_on` constructs it.
#[allow(dead_code)] // The host wiring that uses it is increment 4.
pub(crate) struct ValidatedConfig<'tx> {
    service: String,
    parent: String,
    tx: &'tx mut Transaction<'static, Sqlite>,
}

#[allow(dead_code)] // The host wiring that calls it is increment 4.
impl ProvisionerConfig {
    /// A misconfiguration is an error, never `Unavailable`: the parent is not
    /// a home or is the workspace root, the service is not an `agent`, or the
    /// service lacks Manage on the parent.
    pub(crate) async fn validate_on<'tx>(
        &self,
        tx: &'tx mut Transaction<'static, Sqlite>,
    ) -> Result<ValidatedConfig<'tx>> {
        if self.parent == KERNEL_ROOT_ID {
            return Err(Error::engine(
                "designated parent must not be the workspace root",
            ));
        }
        let parent_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM kernel_roots WHERE root_id=?)")
                .bind(&self.parent)
                .fetch_one(&mut **tx)
                .await?;
        if !parent_exists {
            return Err(Error::engine("designated parent is not a home"));
        }
        if principal_kind(tx, &self.service).await?.as_deref() != Some("agent") {
            return Err(Error::engine("provisioning service is not an agent"));
        }
        let capability = super::slots_eval::capability_on(tx, &self.service, &self.parent).await?;
        if !capability.allows(Capability::Manage) {
            return Err(Error::engine(
                "provisioning service lacks Manage on the designated parent",
            ));
        }
        Ok(ValidatedConfig {
            service: self.service.clone(),
            parent: self.parent.clone(),
            tx,
        })
    }
}

/// The sole appender of `kernel.home_created_for.v1`. It builds the event: the
/// actor and parent come from the validated configuration and the policy is
/// not a parameter, so a caller cannot choose either. The sealed route runs
/// admission in the same transaction, and the fold fixes owner and policy.
/// Returns the logged event; its `record_id` is the new home.
#[allow(dead_code)] // The provisioner that calls it is increment 4.
pub(crate) async fn append_home_for_in(
    db: &Db,
    acts: &mut crate::act::ActAllocation,
    config: ValidatedConfig<'_>,
    owner: &str,
    slot: &str,
) -> Result<EventRow> {
    let ValidatedConfig {
        service,
        parent,
        tx,
    } = config;
    crate::store::append_kernel_slot_in(
        db,
        tx,
        AppendSpec {
            record_id: Uuid::new_v4().to_string(),
            event_type: HOME_CREATED_FOR.into(),
            payload: serde_json::to_value(HomeCreatedForPayload {
                parent_id: parent,
                owner_id: owner.into(),
                slot: slot.into(),
            })?,
            actor: Some(service),
        },
        acts,
    )
    .await
}
