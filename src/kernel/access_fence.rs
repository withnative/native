//! Access-input classification of v2 content events, for a future per-principal
//! cross-request visible-set cache (Native b171a9d, slice 1: the fence only).
//!
//! Semantically inert: nothing in production consults it yet. It records, next
//! to the engine's event types, which events can change who sees which records,
//! so a cache can validate itself from the event delta after its stamp:
//!
//! * [`AccessClass::NoEffect`] writes no visibility input: advance the cursor.
//! * [`AccessClass::PatchClosure`] can change visibility only for its subject
//!   record and the subject's reverse `part_of` closure (comments and
//!   attachments inherit access from their terminal bearer), bounded by
//!   [`crate::authorization::MAX_DERIVED_BEARER_DEPTH`]; overflow recomputes.
//! * [`AccessClass::PatchHome`] creates a fresh leaf home (no records yet); a
//!   cache must evaluate the new home's scope for each cached principal.
//! * [`AccessClass::RecomputePrincipals`] names the principals or accounts it
//!   affects; recompute only those.
//! * [`AccessClass::RecomputeAll`] has an affected set the gate's own code
//!   cannot bound (policy, roster, topology): the conservative fallback that
//!   invalidates the database's bounded cache. Unknown types land here.
//!
//! Ordinary content (creates, edits, deletes, comments, links) is never
//! `RecomputeAll`. Writers that change visibility inputs without appending a
//! content event bump [`crate::db::Db::bump_access_generation`] instead.

use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // consumed by the slice 2 cache (Native b171a9d); exercised by kernel_v2 tests
pub(crate) enum AccessClass {
    NoEffect,
    PatchClosure,
    PatchHome,
    RecomputePrincipals,
    RecomputeAll,
}

/// Every explicitly classified event-type stem: the text between `kernel.`
/// and the final `.version`. This table is the single source of truth for
/// [`class_of`] and for the stored-visibility marking trigger, which generates
/// its typed `content_events` marks from it (design 73ad275 M8). No stem here
/// starts with a [`PREFIX_CLASSES`] prefix, so lookup order cannot matter.
pub(crate) const STEM_CLASSES: &[(&str, AccessClass)] = {
    use AccessClass::*;
    &[
        // Content, history, receipts, runs, providers, apps, presentation.
        ("legacy_recorded", NoEffect),
        ("import_receipt", NoEffect),
        ("v1_state_imported", NoEffect),
        ("provider_outcome", NoEffect),
        ("body_set", NoEffect),
        ("facet_observed", NoEffect),
        ("metadata_set", NoEffect),
        ("archive_changed", NoEffect),
        ("attachment_bound", NoEffect),
        ("mcp_write_receipt_recorded", NoEffect),
        ("mcp_write_fenced", NoEffect),
        ("run_opened", NoEffect),
        ("run_closed", NoEffect),
        ("run_intent_set", NoEffect),
        ("artifact_closure_activated", NoEffect),
        ("artifact_excluded", NoEffect),
        ("saved_tab_changed", NoEffect),
        ("message_state", NoEffect),
        ("message_command_committed", NoEffect),
        ("message_destination_imported", NoEffect),
        ("message_destination_set", NoEffect),
        ("app_state_imported", NoEffect),
        ("comment_anchor_imported", NoEffect),
        ("comment_anchor_set", NoEffect),
        ("comment_anchor_removed", NoEffect),
        ("instruction_binding_imported", NoEffect),
        ("canvas_activated", NoEffect),
        ("canvas_batch_committed", NoEffect),
        ("package_adopted", NoEffect),
        ("definition_adopted", NoEffect),
        ("import_source_head", NoEffect),
        ("webhook_accepted", NoEffect),
        ("webhook_configured", NoEffect),
        ("webhook_revoked", NoEffect),
        ("webhook_diagnostic", NoEffect),
        ("app_source_published", NoEffect),
        ("app_install_recorded", NoEffect),
        ("app_install_adopted", NoEffect),
        ("app_install_removed", NoEffect),
        ("workspace_app_added", NoEffect),
        ("workspace_app_removed", NoEffect),
        ("app_installs_activated", NoEffect),
        ("workspace_metadata_imported", NoEffect),
        ("link_added", NoEffect),
        ("link_removed", NoEffect),
        ("generic_link_note_updated", NoEffect),
        ("generic_link_note_imported", NoEffect),
        ("persona_registered", NoEffect),
        ("persona_retired", NoEffect),
        ("notification_preference_set", NoEffect),
        ("publication_changed", NoEffect),
        ("schema_config_written", NoEffect),
        ("vocabulary_mutated", NoEffect),
        ("account_config_bound", NoEffect),
        ("identity_binding_added", NoEffect),
        ("identity_binding_removed", NoEffect),
        ("identity_binding_reconciled", NoEffect),
        ("slot_provisioned", NoEffect),
        ("slot_replaced", NoEffect),
        // Fresh service or run principals: no existing caller's set changes.
        ("principal_created", NoEffect),
        ("host_transform_created", NoEffect),
        ("host_import_created", NoEffect),
        // Links: only `part_of` is a visibility input (refined by payload).
        ("generic_link_added", PatchClosure),
        ("generic_link_imported", PatchClosure),
        ("generic_link_removed", PatchClosure),
        ("generic_link_removal_imported", PatchClosure),
        // Record placement, ownership, type, existence and message rows.
        ("record_created", PatchClosure),
        ("import_record_created", PatchClosure),
        ("record_revised", PatchClosure),
        ("import_state", PatchClosure),
        ("message_created", PatchClosure),
        ("import_removed", PatchClosure),
        ("record_deleted", PatchClosure),
        ("record_rehomed", PatchClosure),
        ("record_type_corrected", PatchClosure),
        ("import_state_delta", PatchClosure),
        ("import_home", PatchHome),
        ("home_created", PatchHome),
        ("home_created_for", PatchHome),
        ("hosted_membership", RecomputePrincipals),
        ("hosted_offboarding", RecomputePrincipals),
        ("import_home_policy", RecomputeAll),
        ("import_member_policy", RecomputeAll),
        ("home_policy_replaced", RecomputeAll),
        ("import_home_delta", RecomputeAll),
        ("root_created", RecomputeAll),
        ("root_admin_bootstrapped", RecomputeAll),
        ("membership_bundle_defined", RecomputeAll),
        ("membership_bundle_updated", RecomputeAll),
        ("import_members_roster", RecomputeAll),
        ("import_hosted_accounts", RecomputeAll),
    ]
};

/// Stem families classified by prefix rather than by exact stem.
pub(crate) const PREFIX_CLASSES: &[(&str, AccessClass)] = &[
    ("app_catalog_", AccessClass::NoEffect),
    ("app_action_", AccessClass::NoEffect),
    ("hcp_", AccessClass::NoEffect),
    ("named_view_", AccessClass::NoEffect),
];

/// The stem of a `kernel.<stem>.<version>` event type, exactly as
/// [`class_of`] reads it: the text between the `kernel.` prefix and the last
/// `.`. `None` for any other shape.
pub(crate) fn stem_of(event_type: &str) -> Option<&str> {
    let name = event_type.strip_prefix("kernel.")?;
    let (stem, _version) = name.rsplit_once('.')?;
    Some(stem)
}

/// The explicit class of a known engine event type, before payload
/// refinement. `None` means unclassified, which callers treat as
/// [`AccessClass::RecomputeAll`].
#[allow(dead_code)] // consumed by the slice 2 cache (Native b171a9d); exercised by kernel_v2 tests
pub(crate) fn class_of(event_type: &str) -> Option<AccessClass> {
    static EXACT: std::sync::OnceLock<std::collections::HashMap<&'static str, AccessClass>> =
        std::sync::OnceLock::new();
    let stem = stem_of(event_type)?;
    let exact = EXACT.get_or_init(|| STEM_CLASSES.iter().copied().collect());
    exact.get(stem).copied().or_else(|| {
        PREFIX_CLASSES
            .iter()
            .find(|(prefix, _)| stem.starts_with(prefix))
            .map(|(_, class)| *class)
    })
}

/// The access class of one appended event. `subject_is_home` is whether the
/// event's record id is a home (`kernel_roots`): moving a home record changes
/// inherited access for its whole subtree.
#[allow(dead_code)] // consumed by the slice 2 cache (Native b171a9d); exercised by kernel_v2 tests
pub(crate) fn classify(event_type: &str, payload: &Value, subject_is_home: bool) -> AccessClass {
    use AccessClass::*;
    let Some(class) = class_of(event_type) else {
        return RecomputeAll;
    };
    let stem = event_type
        .strip_prefix("kernel.")
        .and_then(|name| name.rsplit_once('.'))
        .map(|(stem, _)| stem)
        .unwrap_or_default();
    match stem {
        "generic_link_added"
        | "generic_link_imported"
        | "generic_link_removed"
        | "generic_link_removal_imported" => {
            match payload.get("relationship").and_then(Value::as_str) {
                Some("part_of") | None => PatchClosure,
                Some(_) => NoEffect,
            }
        }
        "import_removed" => match payload.get("kind").and_then(Value::as_str) {
            Some("record") | None => PatchClosure,
            Some(_) => NoEffect,
        },
        "record_rehomed"
            if subject_is_home
                || payload
                    .get("parent_update")
                    .is_some_and(|update| !update.is_null()) =>
        {
            RecomputeAll
        }
        _ => class,
    }
}

/// The persisted access epoch (Native b171a9d, slice 2 mechanism): derived
/// accelerator metadata, never an authorization input and never canonical.
/// One row, seeded from a random positive base and only ever incremented.
/// Every writer that changes visibility inputs without appending a content
/// event (full projection rebuild, preparation, the policy-log projector)
/// bumps it inside its own transaction, before commit. A future cache reads
/// it in the same snapshot as its cursor, so a rebuild through any handle or
/// process is visible to every reader without a post-commit window.
///
/// Excluded by exact name from the projection digest and the standby schema
/// inventory: two files with identical events may hold different epochs.
/// Created lazily, only by serving start (as Slice B #3234 creates its cache
/// tables), never by schema preparation, inspection, cutover, standby or member
/// paths. A file without the table has no epoch, which a cache must treat as
/// "do not cache"; writers bump only an existing table.
pub(crate) const ACCESS_EPOCH_TABLE: &str = "kernel_access_epoch";

const ACCESS_EPOCH_DDL: &str = "CREATE TABLE IF NOT EXISTS kernel_access_epoch (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), epoch INTEGER NOT NULL CHECK (epoch > 0))";

/// A fresh positive epoch: continue from `prior + 1` when recoverable,
/// otherwise a random positive 62-bit base, so a recreated or restored file
/// cannot collide with a value a live process has trusted. Mirrors Slice B's
/// `sql_event_projection::fresh_generation` (#3234); unify once both land.
fn fresh_epoch(prior: Option<i64>) -> i64 {
    if let Some(next) = prior.filter(|p| *p > 0).and_then(|p| p.checked_add(1)) {
        return next;
    }
    let bytes = uuid::Uuid::new_v4().into_bytes();
    let base = i64::from_le_bytes(bytes[..8].try_into().expect("8 bytes")) & (i64::MAX >> 1);
    base.max(1)
}

/// Create and seed the epoch row if absent. Only serving start (when a cache
/// is enabled for a writable serving handle) may call this, in a writer
/// transaction; rebuild, preparation, inspection, cutover, standby and member
/// paths never create it. Until a cache lands nothing calls it.
#[allow(dead_code)] // called by the slice 2 cache's serving start (Native b171a9d); exercised by kernel_v2 tests
pub(crate) async fn ensure_epoch_on(conn: &mut sqlx::SqliteConnection) -> crate::Result<()> {
    sqlx::query(ACCESS_EPOCH_DDL).execute(&mut *conn).await?;
    sqlx::query("INSERT OR IGNORE INTO kernel_access_epoch (singleton, epoch) VALUES (1, ?)")
        .bind(fresh_epoch(None))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Advance the epoch inside the caller's write transaction, before commit,
/// **only if the table exists**. Never creates it: a cache can exist only
/// after serving created the table, and SQLite's writer lock serialises that
/// creation with every rebuild, so a rebuild after creation always bumps and
/// a rebuild before creation predates any cache.
pub(crate) async fn bump_epoch_on(conn: &mut sqlx::SqliteConnection) -> crate::Result<()> {
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='kernel_access_epoch')")
        .fetch_one(&mut *conn)
        .await?;
    if !present {
        return Ok(());
    }
    let current: i64 =
        sqlx::query_scalar("SELECT epoch FROM main.kernel_access_epoch WHERE singleton = 1")
            .fetch_one(&mut *conn)
            .await?;
    sqlx::query("UPDATE main.kernel_access_epoch SET epoch = ? WHERE singleton = 1")
        .bind(fresh_epoch(Some(current)))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The epoch visible in the caller's snapshot, or `None` when the file has
/// no epoch table (an older file, or a read-only copy). Never writes.
#[allow(dead_code)] // consumed by the slice 2 cache (Native b171a9d); exercised by kernel_v2 tests
pub(crate) async fn read_epoch_on(conn: &mut sqlx::SqliteConnection) -> crate::Result<Option<i64>> {
    let present: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM main.sqlite_schema WHERE type='table' AND name='kernel_access_epoch')")
        .fetch_one(&mut *conn)
        .await?;
    if !present {
        return Ok(None);
    }
    Ok(
        sqlx::query_scalar("SELECT epoch FROM main.kernel_access_epoch WHERE singleton = 1")
            .fetch_optional(&mut *conn)
            .await?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stem_table_is_unambiguous() {
        let mut seen = std::collections::BTreeSet::new();
        for (stem, _) in STEM_CLASSES {
            assert!(seen.insert(*stem), "duplicate stem {stem}");
            assert!(
                !stem.contains('.'),
                "stem {stem} contains a version separator"
            );
            for (prefix, _) in PREFIX_CLASSES {
                assert!(
                    !stem.starts_with(prefix),
                    "{stem} is shadowed by prefix {prefix}"
                );
            }
        }
        assert_eq!(class_of("kernel.hcp_read.v1"), Some(AccessClass::NoEffect));
        assert_eq!(
            class_of("kernel.record_created.v2"),
            Some(AccessClass::PatchClosure)
        );
        assert_eq!(class_of("kernel.unknown_thing.v1"), None);
        assert_eq!(class_of("policy.replaced"), None);
        assert_eq!(stem_of("kernel.a.b.v1"), Some("a.b"));
    }

    #[test]
    fn fresh_epoch_is_positive_and_continues_from_prior() {
        for _ in 0..256 {
            assert!(super::fresh_epoch(None) > 0);
        }
        assert_eq!(super::fresh_epoch(Some(41)), 42);
        assert!(
            super::fresh_epoch(Some(0)) > 0,
            "zero is not a recoverable prior"
        );
        assert!(super::fresh_epoch(Some(-5)) > 0);
        assert!(super::fresh_epoch(Some(i64::MAX)) > 0, "overflow reseeds");
    }
}
