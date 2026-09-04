//! The meta-tier projector — the `meta_events` -> meta-projection fold
//! (decision ba9f97e). The exact analogue of `super::project` for the system tier.
//!
//! `project_meta()` applies ONE meta event to `vocabularies`,
//! `vocabulary_values` and `schema_config`. It is the ONLY writer of those
//! tables: every meta mutation is append-event-then-project (see
//! `crate::meta::log`), and the meta rebuild-and-diff
//! (`crate::conformance::rebuild_and_diff_meta`) folds the same events through
//! this same function into a fresh database.
//!
//! Contract, identical to the content projector: DETERMINISTIC, EXACTLY-ONCE,
//! IN-ORDER replay. Timestamps come from the event (`event.created_at`), never
//! from a SQL `DEFAULT`, so two replays of the same log produce byte-identical
//! rows. It is NOT idempotent — the harness replays each event exactly once from
//! an empty database.
//!
//! DELIBERATELY GUARD-FREE. The lifecycle guards (no hard delete of a seeded or
//! referenced value, no alias chains, no cross-vocabulary alias, pack rows are
//! seed-only) live at the WRITE path in `crate::meta`, not here — the same split
//! the content tier already makes. A guard here would re-run at replay against a
//! half-built database and fail rebuilds that the live write legitimately
//! allowed: `delete_value`'s referenced-by-`facet_values` check, for instance,
//! reads a content-tier table that the meta rebuild's fresh database does not
//! populate at all. Guards decide whether an event may be APPENDED; the fold's
//! only job is to reproduce what was appended.

use sqlx::SqliteConnection;

use crate::error::{Error, Result};
use crate::meta::events::{
    MetaEventRow, SchemaConfigSetPayload, VocabValueAliasedPayload, VocabValueGlossSetPayload,
    VocabValueMetadataSetPayload, VocabValueProposedPayload, VocabValueReorderedPayload,
    VocabularyCreatedPayload,
};

fn parse_payload<T: serde::de::DeserializeOwned>(event: &MetaEventRow) -> Result<T> {
    let Some(payload) = event.payload.as_deref() else {
        return Err(Error::engine(format!(
            "meta event {} ({}) has no payload",
            event.id, event.event_type
        )));
    };
    Ok(serde_json::from_str(payload)?)
}

/// Apply ONE meta event to the meta projections.
pub async fn project_meta(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    match event.event_type.as_str() {
        "vocabulary.created" => vocabulary_created(conn, event).await,
        "vocabulary.deleted" => vocabulary_deleted(conn, event).await,
        "vocab_value.proposed" => vocab_value_proposed(conn, event).await,
        "vocab_value.promoted" => vocab_value_status(conn, event, "active", true).await,
        "vocab_value.deprecated" => vocab_value_status(conn, event, "deprecated", false).await,
        "vocab_value.aliased" => vocab_value_aliased(conn, event).await,
        "vocab_value.reordered" => vocab_value_reordered(conn, event).await,
        "vocab_value.gloss_set" => vocab_value_gloss_set(conn, event).await,
        "vocab_value.metadata_set" => vocab_value_metadata_set(conn, event).await,
        "vocab_value.deleted" => vocab_value_deleted(conn, event).await,
        "schema_config.set" => schema_config_set(conn, event).await,
        other => Err(Error::engine(format!("unknown meta event type: {other}"))),
    }
}

/// Fold a whole meta log into a (fresh) database, in order.
pub async fn replay_meta(conn: &mut SqliteConnection, events: &[MetaEventRow]) -> Result<()> {
    for event in events {
        project_meta(conn, event).await?;
    }
    Ok(())
}

async fn vocabulary_created(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabularyCreatedPayload = parse_payload(event)?;
    sqlx::query("INSERT INTO vocabularies (id, name, created_at) VALUES (?, ?, ?)")
        .bind(&event.subject_id)
        .bind(&p.name)
        .bind(&event.created_at)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// `vocabulary_values` cascade-delete off their parent vocabulary in the frozen
/// DDL, and `crate::db` enables `PRAGMA foreign_keys` per connection — so the
/// values go with it here exactly as they do on the live path, without the fold
/// enumerating them. That equivalence is what keeps the rebuild honest: a fold
/// that deleted values explicitly would diverge from a live delete the moment the
/// cascade and the enumeration disagreed.
async fn vocabulary_deleted(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let res = sqlx::query("DELETE FROM vocabularies WHERE id = ?")
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_proposed(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueProposedPayload = parse_payload(event)?;
    sqlx::query(
        "INSERT INTO vocabulary_values
            (id, vocabulary_id, value, gloss, status, ordinal, terminality, metadata)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&event.subject_id)
    .bind(&p.vocabulary_id)
    .bind(&p.value)
    .bind(&p.gloss)
    .bind(&p.status)
    .bind(p.ordinal)
    .bind(&p.terminality)
    .bind(serde_json::to_string(&p.metadata)?)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

async fn vocab_value_metadata_set(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueMetadataSetPayload = parse_payload(event)?;
    let metadata = serde_json::to_string(&p.metadata)?;
    let res = sqlx::query("UPDATE vocabulary_values SET metadata = ? WHERE id = ?")
        .bind(metadata)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_reordered(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueReorderedPayload = parse_payload(event)?;
    let res = sqlx::query("UPDATE vocabulary_values SET ordinal = ? WHERE id = ?")
        .bind(p.ordinal)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_gloss_set(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueGlossSetPayload = parse_payload(event)?;
    let res = sqlx::query("UPDATE vocabulary_values SET gloss = ? WHERE id = ?")
        .bind(p.gloss)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

/// Promote and deprecate differ only in the status they write and in whether
/// they clear `alias_of`: promotion makes a value canonical, so it cannot remain
/// an alias of something else; deprecation leaves any alias in place.
async fn vocab_value_status(
    conn: &mut SqliteConnection,
    event: &MetaEventRow,
    status: &str,
    clear_alias: bool,
) -> Result<()> {
    let sql = if clear_alias {
        "UPDATE vocabulary_values SET status = ?, alias_of = NULL WHERE id = ?"
    } else {
        "UPDATE vocabulary_values SET status = ? WHERE id = ?"
    };
    let res = sqlx::query(sql)
        .bind(status)
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn vocab_value_aliased(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: VocabValueAliasedPayload = parse_payload(event)?;
    let res = sqlx::query(
        "UPDATE vocabulary_values SET alias_of = ?, status = 'deprecated' WHERE id = ?",
    )
    .bind(&p.alias_of)
    .bind(&event.subject_id)
    .execute(&mut *conn)
    .await?;
    assert_hit(&res, event)
}

async fn vocab_value_deleted(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let res = sqlx::query("DELETE FROM vocabulary_values WHERE id = ?")
        .bind(&event.subject_id)
        .execute(&mut *conn)
        .await?;
    assert_hit(&res, event)
}

async fn schema_config_set(conn: &mut SqliteConnection, event: &MetaEventRow) -> Result<()> {
    let p: SchemaConfigSetPayload = parse_payload(event)?;
    // Unconditional upsert — see SchemaConfigSetPayload: both the user-layer
    // upsert and the pack-layer seed only append when the write landed, so the
    // layer guard belongs at the write path and replaying is a plain apply.
    sqlx::query(
        "INSERT INTO schema_config (id, layer, name, data, applies_to_collection_id, version_lineage, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT (id) DO UPDATE SET layer           = excluded.layer,
                                         name            = excluded.name,
                                         data            = excluded.data,
                                         applies_to_collection_id = excluded.applies_to_collection_id,
                                         version_lineage = excluded.version_lineage",
    )
    .bind(&event.subject_id)
    .bind(&p.layer)
    .bind(&p.name)
    .bind(&p.data)
    .bind(&p.applies_to_collection_id)
    .bind(&p.version_lineage)
    .bind(&event.created_at)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// An update/delete that matched no row means the log describes a mutation of
/// something that is not there — a phantom event. On the content tier the
/// equivalent is `assert_record_live`; here the check is after the fact because
/// the subject's absence is the only failure mode. Erroring rolls back the
/// append transaction on the live path, and fails the rebuild on the replay path
/// — which is the point: the log is the law, so a log that cannot be folded is a
/// failing test rather than a silent no-op.
fn assert_hit(res: &sqlx::sqlite::SqliteQueryResult, event: &MetaEventRow) -> Result<()> {
    if res.rows_affected() == 0 {
        return Err(Error::engine(format!(
            "meta event {} ({}) matched no row: subject {} does not exist",
            event.id, event.event_type, event.subject_id
        )));
    }
    Ok(())
}
