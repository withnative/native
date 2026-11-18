//! Stored visibility and readiness state, slice M1: write-path **marking**
//! (design 73ad275 rev 2.1, §3; task 6ba112fe). Shadow only: nothing reads
//! stored state to answer a request.
//!
//! # What marking is
//!
//! Row triggers on every visibility and projection input (the 15 kernel input
//! tables plus `content_events`, [`MARKED_INPUT_TABLES`](crate::db::writer_contract::MARKED_INPUT_TABLES)) add keys to
//! `main.p_dirty` in the writer's own transaction. A later background drain
//! (slice M2) re-derives the stored state for dirty keys in a transaction of
//! its own and clears them; readers trust a stored row only when nothing it
//! depends on is dirty (the Level 0 fence). Marking is the only accelerator
//! work that ever runs inside a canonical write transaction.
//!
//! # Why it can never refuse or corrupt a write
//!
//! * **M1, body form.** Each trigger statement is
//!   `INSERT INTO p_dirty(kind,key) SELECT '<kind>', <expr> WHERE <expr> IS
//!   NOT NULL ON CONFLICT(kind,key) DO NOTHING`. The upsert clause is not
//!   replaced by the outer statement's conflict policy (an `OR IGNORE` body
//!   would be: rev 2 E5/E6), there is no JSON or lookup that could fail on
//!   malformed data, and a NULL key is skipped rather than violating
//!   `NOT NULL`. The only remaining failures are storage errors, which fail
//!   the canonical write anyway.
//! * **M2, OLD and NEW keys.** INSERT marks NEW, DELETE marks OLD, UPDATE
//!   marks both, including the old and new value of any column that is itself
//!   a key (a record's home, a home's parent, link endpoints).
//! * **M3, no REPLACE** on any input: with `recursive_triggers` off (as every
//!   production pool runs) a REPLACE eviction fires no delete trigger and the
//!   evicted key would be missed (E8). A static scan enforces the ban.
//! * **M4**, the writer-connection contract, lives in
//!   [`crate::db::writer_contract`]: triggers enabled and no TEMP shadow for
//!   the whole lease.
//! * **M5.** Every non-trigger reader of these objects names `main.` (a TEMP
//!   shadow of `p_dirty` would otherwise read as "nothing dirty", E4). Trigger
//!   bodies cannot qualify names, but a main-schema trigger resolves to main.
//! * **M6.** Paths that suppress triggers or rebuild an input table are
//!   registered and invalidate atomically ([`invalidate_all_on`]).
//! * **M7.** Objects are created together and dropped together, triggers
//!   first, because a trigger whose target table is missing would make every
//!   write to its input fail. Full replay DELETEs rows; it never DROPs.
//! * **M8.** `content_events` marks are typed from the access classifier
//!   ([`super::access_fence::STEM_CLASSES`]); an event type the trigger does
//!   not know marks the workspace key `ws`, which is safe and coarse.
//!
//! # Lifecycle in this slice
//!
//! Nothing in production installs the objects yet: older standbys refuse
//! unknown schema objects (rev 2 §7.2). This binary *tolerates* them
//! (certification and digests exclude exactly these objects by name and DDL,
//! [`certification_object`]) and, since slice 2a, never ships them: every
//! owned egress copy runs [`strip_exact_on`] through
//! `crate::export::strip_marking_from_snapshot` (fb924ec Q4), enforced by the
//! copy-site registry in `static_checks`. Creation waits for the production
//! enablement step (plan 5b21bd7).
//!
//! **The floor is the exact set.** A binary strips and exempts only the
//! object set it compiles. A release that predates a table in this set sees
//! a file carrying it as drift: it ships the file unstripped (receivers
//! refuse it) and its own standby coordinates include it (publishing
//! stalls). Creating a set therefore requires every fleet process and every
//! rollback target to compile that exact set, and every later change to the
//! set is a new floor event (brief 87a004f).
//!
//! # Derivation (slice 2b.1)
//!
//! [`drain`] maintains one generation of the families in [`Family::ALL`]
//! (HomeAnchor since 2b.1, Principal since 2b.2a, ScopeAccess since 2b.2b)
//! in bounded batches of
//! their own; [`fence`] is the Level 0 trust check and the per-key lookups.
//! Both are dormant: no production path schedules the drain or reads the
//! stored rows.

use super::*;
use crate::db::writer_contract::ACCELERATOR_PREFIX;
#[cfg(test)]
use crate::db::writer_contract::MARKED_INPUT_TABLES;
use sha2::{Digest, Sha256};

mod derive;
pub(crate) mod drain;
pub(crate) mod fence;

#[cfg(test)]
mod drain_tests;
#[cfg(test)]
mod inventory_tests;
#[cfg(test)]
mod principal_tests;
#[cfg(test)]
mod scope_tests;
#[cfg(test)]
mod sqlite_semantics_tests;
#[cfg(test)]
mod static_checks;
#[cfg(test)]
mod tests;

/// Bumped whenever trigger semantics change without the DDL text changing.
const MARKING_VERSION: u32 = 1;

pub(crate) const DIRTY_TABLE: &str = "p_dirty";
pub(crate) const MARKING_TABLE: &str = "p_marking";
pub(crate) const STATE_TABLE: &str = "p_state";
pub(crate) const GENERATION_TABLE: &str = "p_generation";
pub(crate) const HOME_ANCHOR_TABLE: &str = "p_home_anchor";
pub(crate) const PRINCIPAL_TABLE: &str = "p_principal";
pub(crate) const SCOPE_ACCESS_TABLE: &str = "p_scope_access";

/// The accelerator tables (slice 2b.1, brief 87a004f).
///
/// * `p_generation`: one row per generation of derived state. It holds the
///   authoritative marking era (`marking_since_seq`) and
///   `invalidation_epoch` it was built under; a generation is trusted only
///   while both equal `p_marking`'s. `frontier_seq` is diagnostic, never a
///   cleanliness certificate (canonical rows can change without an event).
///   2b runs exactly one generation; the role column leaves room for a later
///   build-and-swap without reshaping the table.
/// * `p_state`: one row per `(generation, family)`: the derivation version
///   and fingerprint it was built by, readiness, and the flat rebuild cursor.
/// * `p_home_anchor`: the nearest policy anchor of every `kernel_roots` home
///   (NULL for a broken rooted walk). Only rooted homes are materialized; a
///   record home without a root row has no row and is never trusted.
/// * `p_principal`: per `kernel_principals` principal, the workspace
///   admission fence and the transform-service flag (spike B X6). A caller
///   without a row (roster-only, unknown, anonymous) is never trusted.
/// * `p_scope_access`: per principal and policy anchor, the evaluator's
///   three-state result (spike B X1: no app scope): 0 invalid, 1 valid
///   without view, 2 view. A missing pair is never trusted, and is never
///   "valid without view".
const TABLE_DDL: [(&str, &str); 7] = [
    (
        DIRTY_TABLE,
        "CREATE TABLE p_dirty (kind TEXT NOT NULL, key TEXT NOT NULL, PRIMARY KEY (kind, key)) WITHOUT ROWID",
    ),
    (
        MARKING_TABLE,
        "CREATE TABLE p_marking (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)), marking_since_seq INTEGER NOT NULL, invalidation_epoch INTEGER NOT NULL, fingerprint TEXT NOT NULL)",
    ),
    (
        STATE_TABLE,
        "CREATE TABLE p_state (generation INTEGER NOT NULL, family TEXT NOT NULL, derivation_version INTEGER NOT NULL, fingerprint TEXT NOT NULL, ready INTEGER NOT NULL CHECK (ready IN (0, 1)), build_after TEXT, built_through_seq INTEGER NOT NULL, written_at INTEGER NOT NULL, PRIMARY KEY (generation, family)) WITHOUT ROWID",
    ),
    (
        GENERATION_TABLE,
        "CREATE TABLE p_generation (generation INTEGER PRIMARY KEY, token TEXT NOT NULL UNIQUE, role TEXT NOT NULL CHECK (role IN ('building', 'live', 'retiring')), marking_since_seq INTEGER NOT NULL, invalidation_epoch INTEGER NOT NULL, frontier_seq INTEGER NOT NULL, created_at INTEGER NOT NULL)",
    ),
    (
        HOME_ANCHOR_TABLE,
        "CREATE TABLE p_home_anchor (generation INTEGER NOT NULL, home TEXT NOT NULL, anchor TEXT, PRIMARY KEY (generation, home)) WITHOUT ROWID",
    ),
    (
        PRINCIPAL_TABLE,
        "CREATE TABLE p_principal (generation INTEGER NOT NULL, principal TEXT NOT NULL, admitted INTEGER NOT NULL CHECK (admitted IN (0, 1)), transform INTEGER NOT NULL CHECK (transform IN (0, 1)), PRIMARY KEY (generation, principal)) WITHOUT ROWID",
    ),
    (
        SCOPE_ACCESS_TABLE,
        "CREATE TABLE p_scope_access (generation INTEGER NOT NULL, principal TEXT NOT NULL, anchor TEXT NOT NULL, access INTEGER NOT NULL CHECK (access IN (0, 1, 2)), PRIMARY KEY (generation, principal, anchor)) WITHOUT ROWID",
    ),
];

/// Explicit indexes: `(name, table, sql)`. `p_scope_access_by_anchor` makes
/// an anchor key's stored pairs one index range.
const INDEX_DDL: [(&str, &str, &str); 1] = [(
    "p_scope_access_by_anchor",
    SCOPE_ACCESS_TABLE,
    "CREATE INDEX p_scope_access_by_anchor ON p_scope_access (generation, anchor, principal)",
)];

/// Constraint indexes SQLite creates for [`TABLE_DDL`] (`sql` is NULL). They
/// are part of the exact set, and are never dropped directly: they go with
/// their table.
const AUTOINDEXES: [(&str, &str); 1] = [("sqlite_autoindex_p_generation_1", GENERATION_TABLE)];

/// A derived family. Each has one `p_state` row per generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Family {
    /// `p_home_anchor`: home → nearest anchor, over `kernel_roots` homes.
    HomeAnchor,
    /// `p_principal`: admission and transform, over `kernel_principals`.
    Principal,
    /// `p_scope_access`: three-state access per principal × anchor.
    ScopeAccess,
}

/// What a batch does with a dirty key for one dependent family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyAction {
    /// Reset the family's rebuild: every row is re-derived later.
    Escalate,
    /// Refresh or delete the rows keyed by this one key, in this batch.
    Target,
}

#[cfg_attr(not(test), allow(dead_code))]
impl Family {
    pub(crate) const ALL: [Family; 3] =
        [Family::HomeAnchor, Family::Principal, Family::ScopeAccess];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Family::HomeAnchor => "home_anchor",
            Family::Principal => "principal",
            Family::ScopeAccess => "scope_access",
        }
    }

    pub(crate) fn from_str(name: &str) -> Option<Family> {
        Family::ALL.into_iter().find(|f| f.as_str() == name)
    }

    /// How a key of `kind` (one this family depends on) is handled. A
    /// principal's own row is one primary-key row, so its key is targeted;
    /// a roster change can move every principal, and `ws` everything.
    pub(crate) fn key_action(self, kind: KeyKind) -> KeyAction {
        match (self, kind) {
            (Family::Principal, KeyKind::Principal) => KeyAction::Target,
            // The stored pairs of one principal or one anchor: one index
            // range, refreshed or deleted within the batch's allowance.
            (Family::ScopeAccess, KeyKind::Principal | KeyKind::Anchor) => KeyAction::Target,
            _ => KeyAction::Escalate,
        }
    }

    /// The dirty-key kinds whose keys this family's rows depend on. For the
    /// rooted-home subset, every input of the walk (`kernel_roots` rows and
    /// parents, `kernel_policies` existence) marks `home`; `ws` is the
    /// workspace-wide key. Both always escalate in 2b.1.
    pub(crate) fn depends_on(self) -> &'static [KeyKind] {
        match self {
            Family::HomeAnchor => &[KeyKind::Home, KeyKind::Ws],
            // `kernel_principals` rows mark `principal`; every hosted
            // membership event marks `roster`.
            Family::Principal => &[KeyKind::Principal, KeyKind::Roster, KeyKind::Ws],
            // Entries, policy rows and the template and frontier events all
            // mark `anchor` (a policy row also marks `home`, which this
            // family does not need); principals mark `principal`; the roster
            // feeds the members capability.
            Family::ScopeAccess => &[
                KeyKind::Anchor,
                KeyKind::Principal,
                KeyKind::Roster,
                KeyKind::Ws,
            ],
        }
    }

    /// Bumped whenever the derivation's meaning changes. A drain only writes
    /// state built by exactly this version and fingerprint.
    pub(crate) fn derivation_version(self) -> i64 {
        match self {
            Family::HomeAnchor | Family::Principal | Family::ScopeAccess => 1,
        }
    }

    /// The derivation fingerprint: version, family, the probe and rebuild
    /// SQL, and the walk's depth cap. Separate from the object-set
    /// [`fingerprint`]: a change here forces a rebuild, never a floor move.
    pub(crate) fn fingerprint(self) -> &'static str {
        static FINGERPRINTS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
        let all = FINGERPRINTS.get_or_init(|| {
            Family::ALL
                .iter()
                .map(|family| {
                    hex::encode(Sha256::digest(
                        serde_json::to_vec(&(
                            family.derivation_version(),
                            family.as_str(),
                            derive::source_sql(*family),
                            MAX_HOME_DEPTH,
                        ))
                        .expect("static derivation description serializes"),
                    ))
                })
                .collect()
        });
        &all[Family::ALL
            .iter()
            .position(|f| *f == self)
            .expect("every family is listed")]
    }
}

/// A dirty-key kind. Keys are opaque text; `roster` and `ws` are singletons
/// keyed by the empty string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum KeyKind {
    /// One record: its row-local cells and every dependent row through it.
    Rec,
    /// One home (a `kernel_roots` row): placement and the anchor walk.
    Home,
    /// One policy anchor: its entries, templates and frontiers.
    Anchor,
    /// One principal's directory row.
    Principal,
    /// One app installation scope: `principal || x'1f' || package`.
    Scope,
    /// The workspace roster (hosted membership), read at admission.
    Roster,
    /// Everything: an input the marking cannot attribute more precisely.
    Ws,
}

impl KeyKind {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) const ALL: [KeyKind; 7] = [
        KeyKind::Rec,
        KeyKind::Home,
        KeyKind::Anchor,
        KeyKind::Principal,
        KeyKind::Scope,
        KeyKind::Roster,
        KeyKind::Ws,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            KeyKind::Rec => "rec",
            KeyKind::Home => "home",
            KeyKind::Anchor => "anchor",
            KeyKind::Principal => "principal",
            KeyKind::Scope => "scope",
            KeyKind::Roster => "roster",
            KeyKind::Ws => "ws",
        }
    }
}

/// When a mark applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum When {
    /// INSERT (NEW), DELETE (OLD) and UPDATE (OLD and NEW).
    Always,
    /// UPDATE only, and only when this key column changed (OLD and NEW).
    /// INSERT and DELETE are already covered by an `Always` mark on the row.
    KeyChanged(&'static str),
}

/// One key a row contributes. `expr` is written over the row alias `{r}`.
#[derive(Clone, Copy, Debug)]
struct Mark {
    kind: KeyKind,
    expr: &'static str,
    when: When,
}

const fn always(kind: KeyKind, expr: &'static str) -> Mark {
    Mark {
        kind,
        expr,
        when: When::Always,
    }
}

const fn on_change(kind: KeyKind, column: &'static str, expr: &'static str) -> Mark {
    Mark {
        kind,
        expr,
        when: When::KeyChanged(column),
    }
}

/// Per-table trigger keys (design §2.2, M2).
struct InputSpec {
    table: &'static str,
    marks: &'static [Mark],
    /// `UPDATE OF` columns; `None` means every update marks.
    update_of: Option<&'static [&'static str]>,
}

const RECORD_ID: &[Mark] = &[always(KeyKind::Rec, "{r}.record_id")];

/// The kernel input tables. `content_events` is generated separately (M8).
const KERNEL_INPUTS: &[InputSpec] = &[
    InputSpec {
        table: "kernel_records",
        marks: &[
            always(KeyKind::Rec, "{r}.id"),
            on_change(KeyKind::Home, "home_id", "{r}.home_id"),
        ],
        update_of: None,
    },
    InputSpec {
        table: "kernel_roots",
        marks: &[
            always(KeyKind::Home, "{r}.root_id"),
            on_change(KeyKind::Home, "parent_id", "{r}.parent_id"),
        ],
        update_of: None,
    },
    InputSpec {
        table: "kernel_policies",
        // The anchor's policy, and the home key the dependency walk probes.
        marks: &[
            always(KeyKind::Anchor, "{r}.root_id"),
            always(KeyKind::Home, "{r}.root_id"),
        ],
        update_of: None,
    },
    InputSpec {
        table: "kernel_policy_entries",
        marks: &[always(KeyKind::Anchor, "{r}.root_id")],
        update_of: None,
    },
    InputSpec {
        table: "kernel_principals",
        marks: &[always(KeyKind::Principal, "{r}.principal_id")],
        update_of: None,
    },
    InputSpec {
        table: "kernel_generic_links",
        marks: &[
            always(KeyKind::Rec, "{r}.source_id"),
            always(KeyKind::Rec, "{r}.target_id"),
        ],
        // Note-only and event_seq-only rewrites change no derived value.
        update_of: Some(&["relationship", "active", "source_id", "target_id"]),
    },
    InputSpec {
        table: "kernel_import_tombstones",
        marks: RECORD_ID,
        update_of: None,
    },
    InputSpec {
        table: "kernel_record_fields",
        marks: RECORD_ID,
        update_of: None,
    },
    InputSpec {
        table: "kernel_messages",
        marks: &[always(KeyKind::Rec, "{r}.message_id")],
        update_of: None,
    },
    InputSpec {
        table: "kernel_facets",
        marks: RECORD_ID,
        update_of: None,
    },
    InputSpec {
        table: "kernel_record_metadata",
        marks: RECORD_ID,
        update_of: None,
    },
    InputSpec {
        table: "kernel_lifecycle",
        marks: RECORD_ID,
        update_of: None,
    },
    InputSpec {
        table: "kernel_legacy_sql_events",
        marks: RECORD_ID,
        update_of: None,
    },
    InputSpec {
        table: "kernel_app_installs",
        marks: &[always(
            KeyKind::Scope,
            "{r}.principal || char(31) || {r}.package",
        )],
        update_of: None,
    },
    InputSpec {
        table: "kernel_record_bodies",
        marks: RECORD_ID,
        update_of: None,
    },
];

/// Only marking requires this guard: a disabled `p_marking` row (or a
/// missing one) turns every trigger into a no-op without DDL.
const ENABLED_GUARD: &str = "EXISTS (SELECT 1 FROM p_marking WHERE singleton = 1 AND enabled = 1)";

/// One marking statement. The target is unqualified because trigger bodies
/// cannot qualify table names; a main-schema trigger resolves to main.
fn mark_statement(kind: &str, key: &str, condition: Option<&str>) -> String {
    let mut predicate = format!("{key} IS NOT NULL");
    if let Some(condition) = condition {
        predicate.push_str(" AND ");
        predicate.push_str(condition);
    }
    format!(
        "INSERT INTO {DIRTY_TABLE}(kind, key) SELECT '{kind}', {key} WHERE {predicate} ON CONFLICT(kind, key) DO NOTHING;"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Insert,
    Update,
    Delete,
}

impl Op {
    const ALL: [Op; 3] = [Op::Insert, Op::Update, Op::Delete];
    fn sql(self) -> &'static str {
        match self {
            Op::Insert => "INSERT",
            Op::Update => "UPDATE",
            Op::Delete => "DELETE",
        }
    }
    fn suffix(self) -> &'static str {
        match self {
            Op::Insert => "insert",
            Op::Update => "update",
            Op::Delete => "delete",
        }
    }
}

fn kernel_trigger(spec: &InputSpec, op: Op) -> (String, String) {
    let name = format!("p_mark_{}_{}", spec.table, op.suffix());
    let rows: &[&str] = match op {
        Op::Insert => &["NEW"],
        Op::Delete => &["OLD"],
        Op::Update => &["OLD", "NEW"],
    };
    let mut body = Vec::new();
    for mark in spec.marks {
        let condition = match (mark.when, op) {
            (When::Always, _) => None,
            (When::KeyChanged(column), Op::Update) => {
                Some(format!("OLD.{column} IS NOT NEW.{column}"))
            }
            (When::KeyChanged(_), _) => continue,
        };
        for row in rows {
            body.push(mark_statement(
                mark.kind.as_str(),
                &mark.expr.replace("{r}", row),
                condition.as_deref(),
            ));
        }
    }
    let of = match (op, spec.update_of) {
        (Op::Update, Some(columns)) => format!(" OF {}", columns.join(", ")),
        _ => String::new(),
    };
    let sql = format!(
        "CREATE TRIGGER {name} AFTER {}{of} ON {} WHEN {ENABLED_GUARD} BEGIN {} END",
        op.sql(),
        spec.table,
        body.join(" ")
    );
    (name, sql)
}

/// The typed key buckets of `content_events` inserts (M8), beyond the
/// `rec(record_id)` every event marks. Each stem here must be classified by
/// the access fence; every `RecomputeAll` stem must appear here, and every
/// `RecomputePrincipals` stem marks `roster` automatically. A test enforces
/// all three.
const EVENT_SCOPES: &[(&str, KeyKind)] = &[
    // Hosted member-policy templates and home/policy frontiers, read from the
    // log at visibility time (`POLICY_TEMPLATES_SQL`, `POLICY_FRONTIERS_SQL`,
    // `current_member_policy_on`). Keyed by the event's record: the home.
    ("import_member_policy", KeyKind::Anchor),
    ("home_policy_replaced", KeyKind::Anchor),
    ("import_home", KeyKind::Anchor),
    ("import_home_delta", KeyKind::Anchor),
    ("import_home_policy", KeyKind::Anchor),
    // Roster and membership state read at admission.
    ("import_members_roster", KeyKind::Roster),
    ("import_hosted_accounts", KeyKind::Roster),
    ("membership_bundle_defined", KeyKind::Roster),
    ("membership_bundle_updated", KeyKind::Roster),
    // Workspace topology bootstrap: once per workspace, so coarse is free.
    ("root_created", KeyKind::Ws),
    ("root_admin_bootstrapped", KeyKind::Ws),
];

/// The stems that mark `kind` on insert, generated from the classifier.
fn event_stems(kind: KeyKind) -> Vec<&'static str> {
    let mut stems: Vec<&'static str> = super::access_fence::STEM_CLASSES
        .iter()
        .filter(|(stem, class)| {
            EVENT_SCOPES.contains(&(*stem, kind))
                || (kind == KeyKind::Roster
                    && *class == super::access_fence::AccessClass::RecomputePrincipals)
        })
        .map(|(stem, _)| *stem)
        .collect();
    stems.sort_unstable();
    stems.dedup();
    stems
}

/// For a `kernel.`-prefixed type, `.<stem>.`: the text between the first
/// and the last `.`, wrapped in dots. `trim` with every non-dot character of
/// the value as its trim set strips `kernel` from the front and the version
/// from the back, so this is the access fence's `stem_of` (an `rsplit_once`
/// on the last dot), dots inside the stem included. Only functions the
/// enrolled-storage authorizer admits are used (`substr`, `trim`, `replace`,
/// `glob`).
const TYPE_STEM_SQL: &str = "trim(NEW.type, replace(NEW.type, '.', ''))";

fn dotted_stem(stem: &str) -> String {
    assert!(
        stem.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "event stem {stem} must be a plain identifier"
    );
    format!("'.{stem}.'")
}

/// The typed key kind for one event, as SQL: `'anchor'`, `'roster'`, `'ws'`
/// or NULL for an ordinary event. One `CASE` over the dotted stem, so the
/// common case costs one string computation and a run of comparisons; an
/// `IN (…)` list here would build an ephemeral index on every firing. The
/// prefix families are matched with `GLOB 'kernel.<prefix>*.*'`, which is
/// `stem_of(..).starts_with(prefix)` exactly. Anything unclassified is `ws`.
fn event_kind_sql() -> String {
    use super::access_fence::{PREFIX_CLASSES, STEM_CLASSES};
    let typed =
        [KeyKind::Anchor, KeyKind::Roster, KeyKind::Ws].map(|kind| (kind, event_stems(kind)));
    let mut arms = Vec::new();
    // Ordinary stems first: they are nearly every event.
    for (stem, _) in STEM_CLASSES {
        if !typed.iter().any(|(_, stems)| stems.contains(stem)) {
            arms.push(format!("WHEN {} THEN NULL", dotted_stem(stem)));
        }
    }
    for (kind, stems) in &typed {
        for stem in stems {
            arms.push(format!(
                "WHEN {} THEN '{}'",
                dotted_stem(stem),
                kind.as_str()
            ));
        }
    }
    let prefixes = PREFIX_CLASSES
        .iter()
        .map(|(prefix, _)| {
            // `_` is literal in GLOB; prefixes never contain `*`, `?` or `[`.
            let _ = dotted_stem(prefix);
            format!("NEW.type GLOB 'kernel.{prefix}*.*'")
        })
        .collect::<Vec<_>>()
        .join(" OR ");
    format!(
        "CASE WHEN substr(NEW.type, 1, 7) = 'kernel.' THEN CASE {TYPE_STEM_SQL} {} ELSE CASE WHEN {prefixes} THEN NULL ELSE 'ws' END END ELSE 'ws' END",
        arms.join(" ")
    )
}

fn content_event_triggers() -> Vec<(String, String)> {
    let insert = [
        mark_statement(KeyKind::Rec.as_str(), "NEW.record_id", None),
        // Anchor marks key the event's record (the policy home); roster and
        // ws are singletons keyed ''.
        format!(
            "INSERT INTO {DIRTY_TABLE}(kind, key) SELECT typed.kind, CASE typed.kind WHEN 'anchor' THEN NEW.record_id ELSE '' END FROM (SELECT {} AS kind) AS typed WHERE typed.kind IS NOT NULL AND (typed.kind <> 'anchor' OR NEW.record_id IS NOT NULL) ON CONFLICT(kind, key) DO NOTHING;",
            event_kind_sql()
        ),
    ];
    // The log is append-only (content_events_no_update/no_delete); these
    // fire only if a path removes those guards, and then mark everything.
    let coarse = mark_statement(KeyKind::Ws.as_str(), "''", None);
    vec![
        (
            "p_mark_content_events_insert".into(),
            format!(
                "CREATE TRIGGER p_mark_content_events_insert AFTER INSERT ON content_events WHEN {ENABLED_GUARD} BEGIN {} END",
                insert.join(" ")
            ),
        ),
        (
            "p_mark_content_events_update".into(),
            format!(
                "CREATE TRIGGER p_mark_content_events_update AFTER UPDATE ON content_events WHEN {ENABLED_GUARD} BEGIN {coarse} END"
            ),
        ),
        (
            "p_mark_content_events_delete".into(),
            format!(
                "CREATE TRIGGER p_mark_content_events_delete AFTER DELETE ON content_events WHEN {ENABLED_GUARD} BEGIN {coarse} END"
            ),
        ),
    ]
}

/// Every marking trigger as `(name, table, sql)`, in creation order.
fn triggers() -> &'static [(String, &'static str, String)] {
    static TRIGGERS: std::sync::OnceLock<Vec<(String, &'static str, String)>> =
        std::sync::OnceLock::new();
    TRIGGERS.get_or_init(|| {
        let mut all = Vec::new();
        for spec in KERNEL_INPUTS {
            for op in Op::ALL {
                let (name, sql) = kernel_trigger(spec, op);
                all.push((name, spec.table, sql));
            }
        }
        for (name, sql) in content_event_triggers() {
            all.push((name, "content_events", sql));
        }
        all
    })
}

/// One `sqlite_schema` row: `(type, name, tbl_name, sql)`.
pub(crate) type SchemaObject = (String, String, String, Option<String>);

/// The exact objects marking owns, sorted as `sqlite_schema` lists them.
pub(crate) fn expected_objects() -> &'static [SchemaObject] {
    static OBJECTS: std::sync::OnceLock<Vec<SchemaObject>> = std::sync::OnceLock::new();
    OBJECTS.get_or_init(|| {
        let mut objects: Vec<SchemaObject> = TABLE_DDL
            .iter()
            .map(|(name, sql)| {
                (
                    "table".into(),
                    (*name).into(),
                    (*name).into(),
                    Some((*sql).into()),
                )
            })
            .chain(
                AUTOINDEXES
                    .iter()
                    .map(|(name, table)| ("index".into(), (*name).into(), (*table).into(), None)),
            )
            .chain(INDEX_DDL.iter().map(|(name, table, sql)| {
                (
                    "index".into(),
                    (*name).into(),
                    (*table).into(),
                    Some((*sql).into()),
                )
            }))
            .chain(triggers().iter().map(|(name, table, sql)| {
                (
                    "trigger".into(),
                    name.clone(),
                    (*table).into(),
                    Some(sql.clone()),
                )
            }))
            .collect();
        objects.sort();
        objects
    })
}

/// The marking fingerprint: version, tables and the exact trigger DDL,
/// including M8's generated type lists. Any semantic change moves it.
pub(crate) fn fingerprint() -> &'static str {
    static FINGERPRINT: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    FINGERPRINT.get_or_init(|| {
        hex::encode(Sha256::digest(
            serde_json::to_vec(&(MARKING_VERSION, expected_objects()))
                .expect("static marking DDL serializes"),
        ))
    })
}

/// Certification, digests and the standby schema inventory exclude exactly
/// these objects: same type, name, table and DDL (rev 2 C1). Anything else
/// carrying the prefix, including a drifted copy of one of them, remains
/// visible to certification and fails it.
pub(crate) fn certification_object(object: &SchemaObject) -> bool {
    expected_objects().binary_search(object).is_ok()
}

/// Table names [`crate::kernel::projection_dump`] must exclude by name.
pub(crate) const TABLES: [&str; 7] = [
    DIRTY_TABLE,
    MARKING_TABLE,
    STATE_TABLE,
    GENERATION_TABLE,
    HOME_ANCHOR_TABLE,
    PRINCIPAL_TABLE,
    SCOPE_ACCESS_TABLE,
];

/// What the file currently holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObjectState {
    /// No accelerator object exists: marking is off.
    Absent,
    /// Exactly the compiled object set.
    Exact,
    /// Anything else: a partial set, an older or newer binary's set, or a
    /// changed definition. Nothing stored may be trusted.
    Drifted,
}

const ACCELERATOR_OBJECTS_SQL: &str = "SELECT type, name, tbl_name, sql FROM main.sqlite_schema WHERE substr(lower(name), 1, 2) = ?1 OR substr(lower(tbl_name), 1, 2) = ?1";

/// Every object that carries the accelerator prefix **or is attached to an
/// accelerator table** (a trigger or index of any name on a `p_*` table,
/// including SQLite's automatic indexes). `DROP TABLE` silently removes
/// attached objects, so the inventory must see all of them.
async fn accelerator_objects_on(conn: &mut SqliteConnection) -> Result<Vec<SchemaObject>> {
    let mut objects: Vec<SchemaObject> = sqlx::query_as(ACCELERATOR_OBJECTS_SQL)
        .bind(ACCELERATOR_PREFIX)
        .fetch_all(&mut *conn)
        .await?;
    objects.sort();
    Ok(objects)
}

/// Classify the file's accelerator objects against the compiled set.
pub(crate) async fn object_state_on(conn: &mut SqliteConnection) -> Result<ObjectState> {
    let objects = accelerator_objects_on(conn).await?;
    Ok(if objects.is_empty() {
        ObjectState::Absent
    } else if objects == expected_objects() {
        ObjectState::Exact
    } else {
        ObjectState::Drifted
    })
}

fn require_transaction(conn: &mut SqliteConnection, what: &str) -> Result<()> {
    if sqlx::Connection::is_in_transaction(&*conn) {
        Ok(())
    } else {
        Err(Error::engine(format!(
            "stored visibility {what} requires the caller's write transaction"
        )))
    }
}

async fn content_head_on(conn: &mut SqliteConnection) -> Result<i64> {
    Ok(
        sqlx::query_scalar("SELECT coalesce(max(seq), 0) FROM main.content_events")
            .fetch_one(&mut *conn)
            .await?,
    )
}

/// A fresh positive epoch that a restored or recreated file cannot share
/// with one a live process trusted.
fn fresh_epoch() -> i64 {
    let bytes = uuid::Uuid::new_v4().into_bytes();
    (i64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")) & (i64::MAX >> 1)).max(1)
}

/// Create the marking objects in the caller's write transaction (M7): the
/// tables, the enabled `p_marking` row starting at the current content head,
/// then the triggers. Idempotent on an exact set; a drifted set is dropped
/// and recreated, which leaves every family untrusted. Refused on files that
/// are not kernel v2.
///
/// No production path calls this yet (see the module documentation).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn install_on(conn: &mut SqliteConnection) -> Result<()> {
    require_transaction(conn, "installation")?;
    let application_id: i64 = sqlx::query_scalar("PRAGMA main.application_id")
        .fetch_one(&mut *conn)
        .await?;
    if application_id != crate::db::V2_APPLICATION_ID {
        return Err(Error::engine(
            "stored visibility marking requires a kernel v2 file",
        ));
    }
    match object_state_on(conn).await? {
        ObjectState::Exact => return Ok(()),
        ObjectState::Drifted => drop_on(conn).await?,
        ObjectState::Absent => {}
    }
    for (_, ddl) in TABLE_DDL {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    for (_, _, ddl) in INDEX_DDL {
        sqlx::query(ddl).execute(&mut *conn).await?;
    }
    let head = content_head_on(conn).await?;
    let epoch = fresh_epoch();
    let now = chrono::Utc::now().timestamp();
    sqlx::query(
        "INSERT INTO main.p_marking (singleton, enabled, marking_since_seq, invalidation_epoch, fingerprint) VALUES (1, 1, ?, ?, ?)",
    )
    .bind(head)
    .bind(epoch)
    .bind(fingerprint())
    .execute(&mut *conn)
    .await?;
    // One generation, built from scratch: every family unready with its
    // cursor at the start. Marking is on in this same transaction, so no
    // change after the build begins can go unmarked.
    sqlx::query(
        "INSERT INTO main.p_generation (generation, token, role, marking_since_seq, invalidation_epoch, frontier_seq, created_at) VALUES (1, ?, 'building', ?, ?, ?, ?)",
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(head)
    .bind(epoch)
    .bind(head)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    for family in Family::ALL {
        sqlx::query(
            "INSERT INTO main.p_state (generation, family, derivation_version, fingerprint, ready, build_after, built_through_seq, written_at) VALUES (1, ?, ?, ?, 0, NULL, ?, ?)",
        )
        .bind(family.as_str())
        .bind(family.derivation_version())
        .bind(family.fingerprint())
        .bind(head)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    }
    for (_, _, sql) in triggers() {
        sqlx::query(sql).execute(&mut *conn).await?;
    }
    Ok(())
}

/// Drop every accelerator object in the caller's transaction: triggers
/// first, so no write can reach a trigger whose target is gone (M7), then
/// every other `p_*` object, including ones a newer binary created. This is
/// the downgrade and drift path (rev 2 C4).
pub(crate) async fn drop_on(conn: &mut SqliteConnection) -> Result<()> {
    require_transaction(conn, "removal")?;
    let objects = accelerator_objects_on(conn).await?;
    // Explicit indexes (non-NULL `sql`) go before tables: an index of a
    // newer binary may sit on a canonical table, where `DROP TABLE` never
    // reaches it. Constraint autoindexes cannot be dropped and go with their
    // table.
    for kind in ["trigger", "view", "index", "table"] {
        for (object_type, name, _, _) in objects
            .iter()
            .filter(|o| o.0 == kind && (kind != "index" || o.3.is_some()))
        {
            sqlx::query(&format!(
                "DROP {} IF EXISTS main.\"{}\"",
                object_type.to_uppercase(),
                name.replace('"', "\"\"")
            ))
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// The egress strip (decision fb924ec Q4; plan 5b21bd7 slice 2a): remove the
/// compiled marking objects from an **owned copy** that is about to leave
/// this process (an export, a standby FULL, a backup), in the caller's
/// transaction on that copy. Never call it on a live source or on an
/// admitted serving generation.
///
/// Whole set or nothing: the copy is stripped only when its complete
/// accelerator inventory (every `p_*` object and every object of any name
/// attached to a `p_*` table) is exactly the compiled set. Anything else,
/// such as a drifted definition, an unknown trigger or an index on a marking
/// table, leaves the copy unchanged, so the receiver's exact schema check
/// refuses it as it does today. `DROP TABLE` would otherwise erase attached
/// unknown objects silently. Returns how many objects were dropped.
pub(crate) async fn strip_exact_on(conn: &mut SqliteConnection) -> Result<usize> {
    strip_on(conn, true).await
}

async fn strip_on(conn: &mut SqliteConnection, require_exact_set: bool) -> Result<usize> {
    require_transaction(conn, "egress strip")?;
    let objects = accelerator_objects_on(conn).await?;
    if require_exact_set && objects != expected_objects() {
        return Ok(0);
    }
    let exact: Vec<&SchemaObject> = objects.iter().filter(|o| certification_object(o)).collect();
    // Constraint autoindexes (NULL `sql`) are dropped with their table.
    for kind in ["trigger", "index", "table"] {
        for (object_type, name, _, _) in exact
            .iter()
            .filter(|o| o.0 == kind && (kind != "index" || o.3.is_some()))
        {
            sqlx::query(&format!(
                "DROP {} main.\"{}\"",
                object_type.to_uppercase(),
                name.replace('"', "\"\"")
            ))
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(exact.len())
}

/// Test-only: the strip without its whole-set guard, which drops exact
/// objects even when unknown objects hang off them. Proves the guard matters.
#[cfg(test)]
pub(crate) async fn strip_without_dependency_guard_for_test(
    conn: &mut SqliteConnection,
) -> Result<usize> {
    strip_on(conn, false).await
}

async fn main_table_exists(conn: &mut SqliteConnection, name: &str) -> Result<bool> {
    Ok(sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type = 'table' AND name = ?)",
    )
    .bind(name)
    .fetch_one(&mut *conn)
    .await?)
}

/// Every family of every generation unready, with its rebuild cursor back
/// at the start, and every generation adopting the current marking era and
/// epoch. Only valid on the exact object set.
const RESET_AND_ADOPT_SQL: [&str; 2] = [
    "UPDATE main.p_state SET ready = 0, build_after = NULL",
    "UPDATE main.p_generation SET marking_since_seq = (SELECT marking_since_seq FROM main.p_marking WHERE singleton = 1), invalidation_epoch = (SELECT invalidation_epoch FROM main.p_marking WHERE singleton = 1) WHERE EXISTS (SELECT 1 FROM main.p_marking WHERE singleton = 1)",
];

/// The SQL of [`invalidate_all_on`] for whichever tables exist. Never
/// refers to a missing table or column, so it cannot fail on a partial or
/// drifted set.
///
/// The epoch bump on `p_marking` is the cross-version contract: a binary
/// that knows a different object set still bumps it, and a generation built
/// under the old epoch is then untrusted until the drain adopts the new one
/// (which also resets it). On the exact set, the same transaction resets
/// and adopts directly ([`RESET_AND_ADOPT_SQL`]). A drifted set keeps only
/// the readiness reset it always had.
fn invalidation_sql(marking: bool, state: bool, exact: bool) -> Vec<&'static str> {
    let mut statements = Vec::new();
    if marking {
        statements.push(
            "UPDATE main.p_marking SET invalidation_epoch = invalidation_epoch + 1 WHERE singleton = 1",
        );
    }
    if exact {
        statements.extend(RESET_AND_ADOPT_SQL);
    } else if state {
        statements.push("UPDATE main.p_state SET ready = 0 WHERE ready <> 0");
    }
    statements
}

/// Atomic invalidation (M6), in the caller's transaction: a new epoch, every
/// family of every generation unready with its cursor reset, and the
/// generations adopting the new era and epoch. A no-op on a file without
/// marking. Required of any path that writes inputs with triggers
/// suppressed, drops or replaces an input or marking trigger, or rebuilds an
/// input table; also the tail of enabling, disabling and replay completion.
pub(crate) async fn invalidate_all_on(conn: &mut SqliteConnection) -> Result<()> {
    let marking = main_table_exists(conn, MARKING_TABLE).await?;
    let state = main_table_exists(conn, STATE_TABLE).await?;
    let exact = object_state_on(conn).await? == ObjectState::Exact;
    for sql in invalidation_sql(marking, state, exact) {
        sqlx::query(sql).execute(&mut *conn).await?;
    }
    Ok(())
}

/// [`invalidate_all_on`] for code that holds a raw rusqlite handle inside
/// its transaction (the working-copy undo inverse).
#[cfg_attr(not(feature = "v2-kernel-probe"), allow(dead_code))]
pub(crate) fn invalidate_all_raw(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let exists = |name: &str| -> rusqlite::Result<bool> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type = 'table' AND name = ?)",
            [name],
            |row| row.get(0),
        )
    };
    let marking = exists(MARKING_TABLE)?;
    let state = exists(STATE_TABLE)?;
    let exact = {
        let mut statement = conn.prepare(ACCELERATOR_OBJECTS_SQL)?;
        let mut objects = statement
            .query_map([ACCELERATOR_PREFIX], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })?
            .collect::<rusqlite::Result<Vec<SchemaObject>>>()?;
        objects.sort();
        objects == expected_objects()
    };
    for sql in invalidation_sql(marking, state, exact) {
        conn.execute(sql, [])?;
    }
    Ok(())
}

/// Turn marking off or on without DDL, atomically with invalidation (§5):
/// disabling leaves every family untrusted; enabling restarts marking at the
/// current head, so every family stays untrusted until rebuilt.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn set_enabled_on(conn: &mut SqliteConnection, enabled: bool) -> Result<()> {
    require_transaction(conn, "enablement")?;
    if !main_table_exists(conn, MARKING_TABLE).await? {
        return Ok(());
    }
    let head = content_head_on(conn).await?;
    sqlx::query(
        "UPDATE main.p_marking SET enabled = ?1, marking_since_seq = CASE WHEN ?1 = 1 AND enabled = 0 THEN ?2 ELSE marking_since_seq END WHERE singleton = 1",
    )
    .bind(i64::from(enabled))
    .bind(head)
    .execute(&mut *conn)
    .await?;
    invalidate_all_on(conn).await
}

/// Marking held across a full projection replay; see [`suspend_for_replay_on`].
pub(crate) struct ReplaySuspension {
    was_enabled: Option<bool>,
}

/// Full replay deletes and refolds every input row. Marking each of those
/// rows would only be thrown away, so the replay suspends marking first and
/// [`finish_replay_on`] resets it in the same transaction.
pub(crate) async fn suspend_for_replay_on(conn: &mut SqliteConnection) -> Result<ReplaySuspension> {
    if !main_table_exists(conn, MARKING_TABLE).await? {
        return Ok(ReplaySuspension { was_enabled: None });
    }
    let was_enabled: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM main.p_marking WHERE singleton = 1")
            .fetch_optional(&mut *conn)
            .await?;
    sqlx::query("UPDATE main.p_marking SET enabled = 0 WHERE singleton = 1")
        .execute(&mut *conn)
        .await?;
    Ok(ReplaySuspension { was_enabled })
}

/// End of a full replay (design §2.3), in its transaction: clear `p_dirty`
/// (DELETE, never DROP: M7), restart marking at the replayed head, and leave
/// every family not ready until rebuilt.
pub(crate) async fn finish_replay_on(
    conn: &mut SqliteConnection,
    suspension: ReplaySuspension,
) -> Result<()> {
    let Some(was_enabled) = suspension.was_enabled else {
        return invalidate_all_on(conn).await;
    };
    if main_table_exists(conn, DIRTY_TABLE).await? {
        sqlx::query("DELETE FROM main.p_dirty")
            .execute(&mut *conn)
            .await?;
    }
    let head = content_head_on(conn).await?;
    sqlx::query("UPDATE main.p_marking SET enabled = ?, marking_since_seq = ? WHERE singleton = 1")
        .bind(was_enabled)
        .bind(head)
        .execute(&mut *conn)
        .await?;
    invalidate_all_on(conn).await
}

/// The marking row, for the derivation slice and tests.
#[derive(Clone, Debug, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct MarkingRow {
    pub enabled: bool,
    pub marking_since_seq: i64,
    pub invalidation_epoch: i64,
    pub fingerprint: String,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn marking_row_on(conn: &mut SqliteConnection) -> Result<Option<MarkingRow>> {
    if !main_table_exists(conn, MARKING_TABLE).await? {
        return Ok(None);
    }
    Ok(sqlx::query_as(
        "SELECT enabled, marking_since_seq, invalidation_epoch, fingerprint FROM main.p_marking WHERE singleton = 1",
    )
    .fetch_optional(&mut *conn)
    .await?)
}

/// Every dirty key, sorted (tests and diagnostics; the drain pages instead).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) async fn dirty_keys_on(conn: &mut SqliteConnection) -> Result<Vec<(String, String)>> {
    if !main_table_exists(conn, DIRTY_TABLE).await? {
        return Ok(Vec::new());
    }
    Ok(
        sqlx::query_as("SELECT kind, key FROM main.p_dirty ORDER BY kind, key")
            .fetch_all(&mut *conn)
            .await?,
    )
}
