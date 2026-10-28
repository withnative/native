//! Private retained-facet read qualification. Never a producer or public route.
//! Current source evidence diagnoses drift; retained SQL is never regenerated.
use super::{
    facet_resolver, source_proof, v2, Pin, Revision, MAX_CARRIER_BYTES, MISSING, REVISION,
};
use crate::{Error, Result};
use serde_json::{json, Value};
use sqlx::SqliteConnection;
use std::{collections::BTreeSet, time::Instant};

#[allow(dead_code)] // Private checkpoint; public v2 resolution still refuses.
pub(super) struct Checked {
    pub definition: v2::Definition,
    pub drift: Drift,
    pub unknown_reason: Option<source_proof::ComparisonReason>,
    pub work: source_proof::Work,
}
/// Unknown means the bounded advisory comparison could not be completed;
/// mandatory access/context/profile and required-presence checks still passed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Drift {
    Unchanged,
    Changed,
    Unknown,
}
/// Owned only by one caller's closure certification budget, never global or
/// across transactions. Complete section evidence is fetched at most once.
#[derive(Default)]
pub(super) struct ComparisonSnapshot {
    head: Option<i64>,
    sources: Option<std::result::Result<Vec<source_proof::Source>, source_proof::ComparisonReason>>,
    work: source_proof::Work,
}
fn budget() -> Error {
    Error::conflict("view_source_changed: retained source comparison budget exceeded")
}
fn check(deadline: Instant) -> Result<()> {
    super::storage::check_deadline(deadline)
}
fn section(s: &v2::Section) -> &'static str {
    match s {
        v2::Section::SchemaConfig => "schema_config",
        v2::Section::Vocabularies => "vocabularies",
        v2::Section::VocabularyValues => "vocabulary_values",
    }
}

/// The host supplies the trusted workspace namespace. The exact immutable
/// revision is loaded from this connection, never from an old Prepared/proof.
/// Requires an explicit read transaction; caller retains it through row staging.
#[allow(dead_code)] // No public route calls this private qualification seam.
pub(super) async fn inspect_on(
    conn: &mut SqliteConnection,
    actor: &str,
    workspace: &str,
    pin: &Pin,
    deadline: Instant,
) -> Result<Checked> {
    inspect_inner(
        conn,
        actor,
        workspace,
        pin,
        deadline,
        source_proof::ScanLimits::default(),
    )
    .await
    .map_err(|error| source_proof::deadline_error(error, deadline))
}
#[cfg(test)]
pub(super) async fn inspect_with_limits_on(
    conn: &mut SqliteConnection,
    actor: &str,
    workspace: &str,
    pin: &Pin,
    deadline: Instant,
    limits: source_proof::ScanLimits,
) -> Result<Checked> {
    inspect_inner(conn, actor, workspace, pin, deadline, limits)
        .await
        .map_err(|error| source_proof::deadline_error(error, deadline))
}
async fn inspect_inner(
    conn: &mut SqliteConnection,
    actor: &str,
    workspace: &str,
    pin: &Pin,
    deadline: Instant,
    limits: source_proof::ScanLimits,
) -> Result<Checked> {
    check(deadline)?;
    {
        let mut handle = conn.lock_handle().await?;
        // SAFETY: SQLx's locked handle exclusively owns the live connection.
        let (auto, state) = unsafe {
            (
                libsqlite3_sys::sqlite3_get_autocommit(handle.as_raw_handle().as_ptr()),
                libsqlite3_sys::sqlite3_txn_state(
                    handle.as_raw_handle().as_ptr(),
                    c"main".as_ptr(),
                ),
            )
        };
        if auto != 0 || state == libsqlite3_sys::SQLITE_TXN_WRITE {
            return Err(Error::conflict(
                "retained source checks require a caller read snapshot",
            ));
        }
    }
    let bearer = pin
        .view_id
        .strip_prefix("native.named-view:")
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::engine(MISSING))?;
    super::closure::require_accessible_bearer_on(conn, actor, bearer, &mut BTreeSet::new(), true)
        .await?;
    let header: Option<(String, String, i64)> = sqlx::query_as(
        "SELECT record_id,type,octet_length(payload) FROM main.content_events WHERE id=?",
    )
    .bind(&pin.revision_id)
    .fetch_optional(&mut *conn)
    .await?;
    if !header.is_some_and(|(record, kind, bytes)| {
        record == bearer && kind == REVISION && (0..=MAX_CARRIER_BYTES as i64).contains(&bytes)
    }) {
        return Err(super::invalid("view_revision_unavailable"));
    }
    // Logical staging can already have created temp.content_events. Retained
    // identity always addresses the immutable main log, not that logical view.
    let (seq, id, record, kind, payload, event_actor, created_at): super::StoredEvent = sqlx::query_as(
        "SELECT seq,id,record_id,type,payload,actor,created_at FROM main.content_events WHERE id=?",
    )
    .bind(&pin.revision_id)
    .fetch_one(&mut *conn)
    .await?;
    #[cfg(test)]
    super::record_revision_access(&id);
    let event = crate::events::EventRow {
        local_seq: seq,
        id,
        record_id: record,
        event_type: kind,
        payload,
        actor: event_actor,
        created_at,
        run_key: None,
        parent_key: None,
        intent: None,
        causal_envelope: crate::events::CausalEnvelopeV1::legacy_unknown(),
        act: None,
    };

    let rev: Revision = super::decode(&event, MAX_CARRIER_BYTES)
        .map_err(|_| super::invalid("view_revision_unavailable"))?;
    let common = rev
        .validate_retained(&event)
        .map_err(|_| super::invalid("view_revision_unavailable"))?;
    if rev.v != 2
        || rev.definition_sha256 != pin.definition_sha256
        || common.query.output.schema_sha256 != pin.schema_sha256
    {
        return Err(super::invalid("view_revision_unavailable"));
    }
    let definition: v2::Definition = serde_json::from_value(rev.definition)?;
    inspect_definition_on(conn, actor, workspace, bearer, definition, deadline, limits).await
}

/// Shared retained interpretation on an already validated immutable carrier.
/// The caller owns this snapshot through source checks and logical staging.
pub(super) async fn inspect_definition_on(
    conn: &mut SqliteConnection,
    actor: &str,
    workspace: &str,
    bearer: &str,
    definition: v2::Definition,
    deadline: Instant,
    limits: source_proof::ScanLimits,
) -> Result<Checked> {
    inspect_definition_shared_on(
        conn,
        actor,
        workspace,
        bearer,
        definition,
        deadline,
        limits,
        &mut ComparisonSnapshot::default(),
    )
    .await
}
#[allow(clippy::too_many_arguments)] // One snapshot/cap shared by a bounded closure.
pub(super) async fn inspect_definition_shared_on(
    conn: &mut SqliteConnection,
    actor: &str,
    workspace: &str,
    bearer: &str,
    definition: v2::Definition,
    deadline: Instant,
    limits: source_proof::ScanLimits,
    snapshot: &mut ComparisonSnapshot,
) -> Result<Checked> {
    // Every node still passes mandatory current checks, including when an
    // earlier comparison exhausted its budget or could not decode a source.
    let (head, work) = mandatory_on(conn, actor, workspace, bearer, &definition, deadline).await?;
    compare_at_on(conn, definition, head, work, deadline, limits, snapshot).await
}
/// Metadata already authorized all retained anchors and checked point presence;
/// its context check is a diagnostic, never an executable serving grant.
pub(super) async fn compare_metadata_on(
    conn: &mut SqliteConnection,
    definition: v2::Definition,
    context: (i64, source_proof::Work),
    deadline: Instant,
) -> Result<Checked> {
    compare_at_on(
        conn,
        definition,
        context.0,
        context.1,
        deadline,
        source_proof::ScanLimits::default(),
        &mut ComparisonSnapshot::default(),
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn compare_at_on(
    conn: &mut SqliteConnection,
    definition: v2::Definition,
    head: i64,
    work: source_proof::Work,
    deadline: Instant,
    limits: source_proof::ScanLimits,
    snapshot: &mut ComparisonSnapshot,
) -> Result<Checked> {
    if snapshot.head.is_some_and(|old| old != head) {
        return Err(Error::conflict("retained comparison snapshot changed"));
    }
    if snapshot.sources.is_none() {
        snapshot.head = Some(head);
        snapshot.work = work;
        snapshot.sources = Some(
            match source_proof::comparison_sources_on(
                conn,
                head,
                &mut snapshot.work,
                deadline,
                limits,
            )
            .await
            {
                Ok(sources) => Ok(sources),
                Err(source_proof::ComparisonFailure::Incomplete(_, reason)) => Err(reason),
                Err(source_proof::ComparisonFailure::Refuse(error)) => return Err(error),
            },
        );
    }
    let manifest = &definition.generated;
    let comparison: source_proof::ComparisonResult<Drift> = async {
        let sources = match snapshot.sources.as_ref().unwrap() {
            Ok(sources) => sources,
            Err(reason) => {
                return Err(source_proof::ComparisonFailure::Incomplete(
                    Error::engine("bounded current comparison unavailable"),
                    *reason,
                ))
            }
        };
        let resolved = facet_resolver::comparison_sources(
            sources,
            &manifest.context.logical_home_id,
            deadline,
        )?;
        let mut drifted = false;
        for old in &manifest.sources {
            check(deadline)?;
            drifted |= !sources.iter().any(|s| {
                s.section == section(&old.section)
                    && s.source_id == old.source_id
                    && s.event_id == old.event_id
                    && s.event_sha256 == old.event_sha256
                    && s.origin == old.origin
            });
        }
        drifted |= compare(manifest, &resolved, deadline)?;
        Ok(if drifted {
            Drift::Changed
        } else {
            Drift::Unchanged
        })
    }
    .await;
    let (drift, unknown_reason) = match comparison {
        Ok(drift) => (drift, None),
        Err(source_proof::ComparisonFailure::Incomplete(_, reason)) => {
            (Drift::Unknown, Some(reason))
        }
        Err(source_proof::ComparisonFailure::Refuse(error)) => return Err(error),
    };
    // Incomplete comparison is never permission to exceed the caller deadline.
    check(deadline)?;
    Ok(Checked {
        definition,
        drift,
        unknown_reason,
        work: snapshot.work,
    })
}

// Compare selected semantic inputs, not executable output. Slot precedence and
// field-key selection come from the validated retained slots and shared cascade.
fn compare(
    m: &v2::Manifest,
    current: &facet_resolver::ResolvedSources<'_>,
    deadline: Instant,
) -> source_proof::ComparisonResult<bool> {
    let effective = crate::query::cascade::facets_for_record_context(
        &current.rows,
        &m.context.r#type,
        m.context.kind.as_deref(),
        Some(&m.context.logical_home_id),
    );
    let old_keys: BTreeSet<_> = m
        .slots
        .iter()
        .flat_map(|s| s.fragments.iter().map(|f| f.key.clone()))
        .collect();
    let keys: BTreeSet<String> = match &m.selection {
        v2::Selection::Keys { keys } => keys.iter().cloned().collect(),
        v2::Selection::All => effective
            .keys()
            .filter(|k| !crate::schema::SPINE_FACET_KEYS.contains(&k.as_str()))
            .cloned()
            .collect(),
    };
    if keys.len() > 18 || keys.iter().any(|k| k.len() > 128) {
        return Err(source_proof::ComparisonFailure::budget(budget()));
    }
    let mut drift = keys != old_keys;
    let vocab_ids: BTreeSet<_> = m
        .vocabularies
        .iter()
        .map(|v| m.sources[v.source].row_id.as_str())
        .collect();
    let mut relevant = BTreeSet::new();
    let mut governance = Vec::new();
    for (index, slot) in m.slots.iter().enumerate() {
        check(deadline)?;
        let home = if slot.scope == v2::Scope::Home {
            Some(m.context.logical_home_id.as_str())
        } else {
            None
        };
        let layer = if slot.layer == v2::Layer::Pack {
            "pack"
        } else {
            "user"
        };
        let mut actual = Vec::new();
        for row in &current.rows {
            check(deadline)?;
            if row.layer != layer
                || row.applies_to_collection_id.as_deref() != home
                || (m.context.kind.is_none() && index % 4 >= 2)
            {
                continue;
            }
            let Some(shape) = row.data.get("shapes").and_then(|s| s.get(&slot.shape_key)) else {
                continue;
            };
            if home.is_some() && shape.is_object() {
                relevant.insert(row.id.clone());
                if relevant.len() + vocab_ids.len() > 32 {
                    return Err(source_proof::ComparisonFailure::budget(budget()));
                }
                if governance.len() >= 64 {
                    return Err(source_proof::ComparisonFailure::budget(budget()));
                }
                governance.push(json!([
                    row.id,
                    slot.shape_key,
                    row.version_lineage,
                    row.created_at
                ]));
            }
            // New unsupported interpretations are advisory; they do not cause
            // A1 to be compiled or interpreted under a new language profile.
            if !shape.is_object() || shape.get("facets").is_some_and(|f| !f.is_object()) {
                return Err(source_proof::ComparisonFailure::unsupported(Error::engine(
                    "unsupported current declaration shape",
                )));
            }
            for key in &keys {
                let Some(raw) = shape.get("facets").and_then(|f| f.get(key)) else {
                    continue;
                };
                relevant.insert(row.id.clone());
                if relevant.len() + vocab_ids.len() > 32 {
                    return Err(source_proof::ComparisonFailure::budget(budget()));
                }
                // Count before cloning/normalizing a current selected fragment.
                crate::query::generated_facets::size(raw, MAX_CARRIER_BYTES)
                    .map_err(|_| source_proof::ComparisonFailure::budget(budget()))?;
                let decl = serde_json::from_value::<v2::Declaration>(raw.clone())
                    .and_then(serde_json::to_value)?;
                actual.push(json!([
                    row.id,
                    key,
                    decl,
                    row.version_lineage,
                    row.created_at
                ]));
            }
        }
        let expected: Vec<_> = slot
            .fragments
            .iter()
            .map(|f| {
                json!([
                    m.sources[f.source].row_id,
                    f.key,
                    f.decl,
                    f.lineage,
                    f.created_at
                ])
            })
            .collect();
        drift |= actual != expected;
    }
    let expected: Vec<_> = m
        .governance_basis
        .iter()
        .map(|g| {
            json!([
                m.sources[g.source].row_id,
                g.shape_key,
                g.lineage,
                g.created_at
            ])
        })
        .collect();
    drift |= governance != expected;
    if relevant.len() + vocab_ids.len() > 32 {
        return Err(source_proof::ComparisonFailure::budget(budget()));
    }
    let mut total = 0;
    let mut counted_vocabularies = BTreeSet::new();
    for vocab in &m.vocabularies {
        check(deadline)?;
        let id = &m.sources[vocab.source].row_id;
        let mut actual = Vec::new();
        for (s, row) in &current.raw {
            check(deadline)?;
            if s.section == "vocabulary_values"
                && row["vocabulary_id"].as_str() == Some(id.as_str())
            {
                if actual.len() >= 64 || row["value"].as_str().is_some_and(|s| s.len() > 512) {
                    return Err(source_proof::ComparisonFailure::budget(budget()));
                }
                actual.push(json!([
                    row["id"],
                    row["value"],
                    row["status"],
                    row.get("alias_of").unwrap_or(&Value::Null)
                ]));
            }
        }
        if counted_vocabularies.insert(id) {
            total += actual.len();
        }
        if actual.len() > 64 || total > 256 {
            return Err(source_proof::ComparisonFailure::budget(budget()));
        }
        actual.sort_by_key(Value::to_string);
        let mut expected: Vec<_> = vocab
            .values
            .iter()
            .map(|v| json!([v.id, v.token, v.status, v.alias_of]))
            .collect();
        expected.sort_by_key(Value::to_string);
        drift |= actual != expected;
    }
    Ok(drift)
}

/// Commit-time mandatory checks only. Frozen advisory comparison is read work;
/// publication preflight carries its owned interval proof through the writer.
pub(super) async fn mandatory_on(
    conn: &mut SqliteConnection,
    actor: &str,
    workspace: &str,
    bearer: &str,
    definition: &v2::Definition,
    deadline: Instant,
) -> Result<(i64, source_proof::Work)> {
    let manifest = &definition.generated;
    if manifest.workspace_id != workspace {
        return Err(Error::engine(MISSING));
    }
    let context =
        source_proof::retained_context_on(conn, actor, bearer, manifest, deadline).await?;
    if definition
        .query
        .relations
        .values()
        .any(|d| matches!(d, super::contract::Dependency::View(_)))
    {
        return Err(super::invalid("view_revision_unavailable")); // facet-1 has only static sources.
    }
    // Mandatory even when comparison later runs out of work or cannot decode
    // current catalog rows. No SQLite preparation/SQL compilation here.
    definition.query.validate_for_preparation()?;
    required_presence_on(conn, definition, deadline).await?;
    Ok(context)
}

pub(super) async fn required_presence_on(
    conn: &mut SqliteConnection,
    definition: &v2::Definition,
    deadline: Instant,
) -> Result<()> {
    let manifest = &definition.generated;
    // Presence is separate from executability or current interpretation. No
    // tombstone scan: present replacements (including reinsertions) are drift.
    for i in facet_resolver::required_sources(manifest) {
        check(deadline)?;
        let s = &manifest.sources[i];
        let present: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM main.kernel_v1_state WHERE section=? AND source_id=?)",
        )
        .bind(section(&s.section))
        .bind(&s.source_id)
        .fetch_one(&mut *conn)
        .await?;
        if !present {
            return Err(Error::engine(MISSING));
        }
    }
    Ok(())
}
