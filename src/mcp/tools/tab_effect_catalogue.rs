//! Engine-owned named-effect catalogue for installed-tab writes (D1 slice 2).
//!
//! This slice extracts what already ships: the triage pair (task `26ba75a`),
//! the Tasks lifecycle arm (task `21f44fc`), and the narrowed facet-set,
//! comment, message.react and title.set rows. Each row owns its arm, its
//! required effect name, its consent shape (historical string effect versus
//! parsed object bound), its reversibility class and its entry-shape
//! predicate, and both lookups below consume the table — so adding a row
//! drives matching and consent, and the metadata cannot drift from the
//! matching. Matching runs against the actual parsed manifest entry, never
//! caller text, and every refusal keeps its existing code and wording at the
//! call site.

use native_artifact_runtime::mdx_v2::{InteractionEffect, InteractionEntry, ValueSource};

/// Consented effect name for the triage pair (canonical home; re-exported by
/// `alpha_tabs` for compatibility).
pub const ALPHA_TRIAGE_SET_EFFECT: &str = "task.triage-set.v1";

/// The single facet the triage pair may move (canonical home; re-exported).
pub const ALPHA_GUARD_FACET: &str = "triage";

/// Consented effect name for the Tasks click slice (canonical home).
pub const TASKS_LIFECYCLE_SET_EFFECT: &str = "tasks.lifecycle-set.v1";

/// Facet key the Tasks click slice may move (canonical home).
pub const TASKS_LIFECYCLE_FACET: &str = "lifecycle";

/// Declared literal value the Tasks click entry must carry (canonical home).
pub const TASKS_LIFECYCLE_TARGET: &str = "in_progress";

/// Lifecycle state a record must be in for the Tasks click (canonical home).
pub const TASKS_LIFECYCLE_SOURCE: &str = "open";

/// Consented effect name for narrowed facet writes (task `81372d1`
/// facet-set slice). Consent is always the object form parsed in
/// `alpha_tabs`; the bare string is refused as unbounded at declaration
/// parse, so this name only ever appears qualified by a bound.
pub const FACET_SET_EFFECT: &str = "records.facet-set.v1";

/// Consented effect name for governed comment posting (task `b9fb9fd`
/// family 1). Consent is always the object form parsed in `alpha_tabs`;
/// the bare string is refused as unbounded at declaration parse. The
/// governed write path rechecks the bound inside the transaction.
pub const COMMENT_CREATE_EFFECT: &str = "comment.create.v1";

/// Byte cap range for one `comment.create` consent bound (UTF-8 bytes,
/// 1..=4096). The effective cap is the minimum of the manifest bound and
/// this consent bound.
pub const COMMENT_CREATE_MAX_BODY_BYTES: usize = 4096;

/// Consented effect name for governed message reactions (task `07ae879`).
/// Consent is always the object form parsed in `alpha_tabs`; the bare string
/// is refused as unbounded at declaration parse. The governed write path
/// rechecks the bound inside the transaction.
pub const MESSAGE_REACT_EFFECT: &str = "message.react.v1";

/// Consented effect name for governed title renames (task `da148be`).
/// Consent is always the object form parsed in `alpha_tabs`; the bare
/// string is refused as unbounded at declaration parse. The governed
/// write path rechecks the bound inside the transaction.
pub const TITLE_SET_EFFECT: &str = "records.title-set.v1";

/// Dormant bounded body replacement; never ordinary facet or title consent.
pub const BODY_SET_EFFECT: &str = "records.body-set.v1";
pub const BODY_SET_MAX_BODY_BYTES: usize = native_artifact_runtime::mdx_v2::BODY_SET_MAX_BODY_BYTES;

/// Catalogue arms, including dormant `BodySet`. `FacetSet` matches any `facet.set` entry the earlier
/// rows do not claim; key/value/need admission happens against the
/// consented object bounds in the guard, never here. `CommentCreate`
/// matches `comment.create` entries for consent parsing and
/// canonicalization. The native.html.v1 path uses the governed comment
/// transaction; other runtimes refuse comment invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TabEffectArm {
    Triage,
    TasksLifecycle,
    FacetSet,
    CommentCreate,
    MessageReact,
    TitleSet,
    BodySet,
}

/// Reversibility class for one catalogue row (D7 slice U1). `Restorable`
/// effects reverse by restoring the prior value; `Additive` effects add
/// new state with no reversal here; `SelfInverse` effects reverse by
/// re-applying the same toggle with the opposite desired state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReversalClass {
    Restorable,
    Additive,
    SelfInverse,
}

/// How a catalogue row's consent is expressed in a declaration (D7 §4C.2
/// N3a). `LegacyString` rows are admitted only by a bare effect-name string
/// in `effects`, which carries no bound and is an alpha-tab-install
/// convention: an app declaration must never gain them. `Object` rows are
/// admitted by a parsed object bound and are source-neutral across
/// declaring-package sources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentShape {
    /// Historical bare-string effect consent; alpha tab installs only.
    LegacyString,
    /// Parsed object-bound consent; any declaring-package source.
    Object,
}

/// One catalogue row: the arm, the effect name the install must consent to,
/// the consent shape, the reversibility class, and the entry-shape
/// predicate. Rows are matched in table order.
#[derive(Clone, Copy)]
pub struct TabEffectEntry {
    pub arm: TabEffectArm,
    pub effect_name: &'static str,
    pub consent: ConsentShape,
    pub reversal: ReversalClass,
    pub matches: fn(&InteractionEntry) -> bool,
}

/// `facet.set` on the `lifecycle` spine key with a declared literal
/// `in_progress` value.
fn tasks_lifecycle_matches(entry: &InteractionEntry) -> bool {
    entry.effect == InteractionEffect::FacetSet
        && entry.facet == TASKS_LIFECYCLE_FACET
        && matches!(&entry.value, Some(ValueSource::Literal { value }) if value.as_str() == Some(TASKS_LIFECYCLE_TARGET))
}

/// Any entry targeting the triage facet. Effect-kind screening (`facet.set`
/// / `facet.unset` vs `record.create`) stays at the call sites, in the same
/// order as before, so this never widens admission.
fn triage_matches(entry: &InteractionEntry) -> bool {
    entry.effect != InteractionEffect::BodySet && entry.facet == ALPHA_GUARD_FACET
}

/// Ordinary facet keys: everything the generic arm may narrow, defined
/// once here and shared by the declaration parser so matcher and consent
/// cannot drift. Spine columns, engine-dispatched keys, record fields and
/// the dedicated triage facet are excluded by existing shared schema
/// semantics — never a new allowlist.
pub fn is_ordinary_facet_key(key: &str) -> bool {
    crate::schema::spine_facet_column(key).is_none()
        && !native_artifact_runtime::mdx_v2::ENGINE_DISPATCHED_FACET_KEYS.contains(&key)
        && !native_artifact_runtime::mdx_v2::RECORD_CREATE_FIELD_KEYS.contains(&key)
        && key != ALPHA_GUARD_FACET
}

/// A `facet.set` entry on an ordinary key that neither earlier row claims.
/// Placed last so triage `facet.set` entries keep the triage arm and its
/// string consent; non-Start lifecycle entries and other protected shapes
/// fall through to the legacy scope refusal, unchanged.
fn facet_set_matches(entry: &InteractionEntry) -> bool {
    entry.effect == InteractionEffect::FacetSet && is_ordinary_facet_key(&entry.facet)
}

/// A `comment.create` entry, matched by effect only. Position, body cap
/// and need admission happen against the consented object bound, never
/// here. The native.html.v1 path writes through the governed comment
/// transaction; other runtimes refuse comment invocation.
fn comment_create_matches(entry: &InteractionEntry) -> bool {
    entry.effect == InteractionEffect::CommentCreate
}

/// A `message.react` entry, matched by effect only (task `07ae879`). Emoji
/// subset and need admission happen against the consented object bound,
/// never here. The native.html.v1 path writes through the governed reaction
/// transaction.
fn message_react_matches(entry: &InteractionEntry) -> bool {
    entry.effect == InteractionEffect::MessageReact
}

/// A `title.set` entry, matched by effect only. Need admission happens
/// against the consented object bound, never here. The native.html.v1
/// path writes through the governed title transaction; other runtimes
/// refuse title invocation.
fn title_set_matches(entry: &InteractionEntry) -> bool {
    entry.effect == InteractionEffect::TitleSet
}

/// The catalogue, in match priority. Lifecycle first preserves the old rule
/// that a lifecycle-shaped entry takes the tasks flow even under a
/// triage-known id; triage second preserves the triage pair; facet-set
/// third admits only `facet.set` entries to object-bound consent; comment
/// fourth matches only `comment.create` entries for object-bound consent
/// and native.html.v1 dispatch; react fifth matches only `message.react`
/// entries for object-bound consent; title matches only `title.set`
/// entries for object-bound consent and native.html.v1 dispatch.
/// Body matches only `body.set` and remains non-executable.
fn body_set_matches(entry: &InteractionEntry) -> bool {
    entry.effect == InteractionEffect::BodySet
}

pub const TAB_EFFECT_CATALOGUE: [TabEffectEntry; 7] = [
    TabEffectEntry {
        arm: TabEffectArm::TasksLifecycle,
        effect_name: TASKS_LIFECYCLE_SET_EFFECT,
        consent: ConsentShape::LegacyString,
        reversal: ReversalClass::Restorable,
        matches: tasks_lifecycle_matches,
    },
    TabEffectEntry {
        arm: TabEffectArm::Triage,
        effect_name: ALPHA_TRIAGE_SET_EFFECT,
        consent: ConsentShape::LegacyString,
        reversal: ReversalClass::Restorable,
        matches: triage_matches,
    },
    TabEffectEntry {
        arm: TabEffectArm::FacetSet,
        effect_name: FACET_SET_EFFECT,
        consent: ConsentShape::Object,
        reversal: ReversalClass::Restorable,
        matches: facet_set_matches,
    },
    TabEffectEntry {
        arm: TabEffectArm::CommentCreate,
        effect_name: COMMENT_CREATE_EFFECT,
        consent: ConsentShape::Object,
        reversal: ReversalClass::Additive,
        matches: comment_create_matches,
    },
    TabEffectEntry {
        arm: TabEffectArm::MessageReact,
        effect_name: MESSAGE_REACT_EFFECT,
        consent: ConsentShape::Object,
        reversal: ReversalClass::SelfInverse,
        matches: message_react_matches,
    },
    TabEffectEntry {
        arm: TabEffectArm::TitleSet,
        effect_name: TITLE_SET_EFFECT,
        consent: ConsentShape::Object,
        reversal: ReversalClass::Restorable,
        matches: title_set_matches,
    },
    TabEffectEntry {
        arm: TabEffectArm::BodySet,
        effect_name: BODY_SET_EFFECT,
        consent: ConsentShape::Object,
        reversal: ReversalClass::Restorable,
        matches: body_set_matches,
    },
];

/// The first catalogue row whose predicate the entry satisfies, if any.
pub fn match_row(entry: &InteractionEntry) -> Option<&'static TabEffectEntry> {
    TAB_EFFECT_CATALOGUE.iter().find(|row| (row.matches)(entry))
}

/// The matched arm, if any.
pub fn match_arm(entry: &InteractionEntry) -> Option<TabEffectArm> {
    match_row(entry).map(|row| row.arm)
}

/// The consented effect name the matched arm requires, read from the row.
/// For `FacetSet` this is the bound family name; the admitting object bound
/// (key, values, need) is resolved separately in the guard.
pub fn required_effect_name(arm: TabEffectArm) -> Option<&'static str> {
    TAB_EFFECT_CATALOGUE
        .iter()
        .find(|row| row.arm == arm)
        .map(|row| row.effect_name)
}

/// How the matched arm's consent is expressed (D7 §4C.2 N3a). `None` for an
/// arm with no catalogue row. Pure table lookup. The pure `effect_bounds`
/// admission reads it, but neither is wired into the production guard chain
/// yet — that integration is N3b.
pub fn consent_shape(arm: TabEffectArm) -> Option<ConsentShape> {
    TAB_EFFECT_CATALOGUE
        .iter()
        .find(|row| row.arm == arm)
        .map(|row| row.consent)
}

/// Reversibility class for a stored write, by its content-event type and
/// facet key. `None` means no catalogue row owns the write (created records,
/// ungoverned spine columns, unknown shapes): not reversible here. Future
/// families add a catalogue row instead of editing the reversal module.
pub fn reversal_class_for_write(event_type: &str, key: &str) -> Option<ReversalClass> {
    let arm = match event_type {
        "record.created" => return None,
        "facet.set" | "facet.unset" if key == ALPHA_GUARD_FACET => TabEffectArm::Triage,
        "facet.set" | "facet.unset" if is_ordinary_facet_key(key) => TabEffectArm::FacetSet,
        "facet.set" | "record.updated" if key == TASKS_LIFECYCLE_FACET => {
            TabEffectArm::TasksLifecycle
        }
        "record.updated" if key == "name" => TabEffectArm::TitleSet,
        _ => return None,
    };
    TAB_EFFECT_CATALOGUE
        .iter()
        .find(|row| row.arm == arm)
        .map(|row| row.reversal)
}

#[cfg(test)]
mod tests {
    use super::{reversal_class_for_write, ReversalClass, TabEffectArm, TAB_EFFECT_CATALOGUE};

    /// Each catalogue row carries its D7 §2.2 reversal class.
    #[test]
    fn catalogue_rows_carry_reversal_class() {
        let class = |arm: TabEffectArm| {
            TAB_EFFECT_CATALOGUE
                .iter()
                .find(|row| row.arm == arm)
                .map(|row| row.reversal)
        };
        assert_eq!(class(TabEffectArm::Triage), Some(ReversalClass::Restorable));
        assert_eq!(
            class(TabEffectArm::TasksLifecycle),
            Some(ReversalClass::Restorable)
        );
        assert_eq!(
            class(TabEffectArm::FacetSet),
            Some(ReversalClass::Restorable)
        );
        assert_eq!(
            class(TabEffectArm::CommentCreate),
            Some(ReversalClass::Additive)
        );
        assert_eq!(
            class(TabEffectArm::MessageReact),
            Some(ReversalClass::SelfInverse)
        );
        assert_eq!(
            class(TabEffectArm::TitleSet),
            Some(ReversalClass::Restorable)
        );
        assert_eq!(
            class(TabEffectArm::BodySet),
            Some(ReversalClass::Restorable)
        );
    }

    /// Stored writes resolve to their row's class by event type and key.
    #[test]
    fn stored_writes_resolve_to_their_row_class() {
        assert_eq!(
            reversal_class_for_write("facet.set", "triage"),
            Some(ReversalClass::Restorable)
        );
        assert_eq!(
            reversal_class_for_write("facet.unset", "effort"),
            Some(ReversalClass::Restorable)
        );
        assert_eq!(
            reversal_class_for_write("record.updated", "lifecycle"),
            Some(ReversalClass::Restorable)
        );
        assert_eq!(
            reversal_class_for_write("record.updated", "name"),
            Some(ReversalClass::Restorable)
        );
        // Declared Restorable does not activate persisted Body Undo.
        assert_eq!(reversal_class_for_write("record.updated", "body"), None);
        assert_eq!(reversal_class_for_write("record.created", "triage"), None);
        assert_eq!(reversal_class_for_write("facet.set", "owner"), None);
    }
}
