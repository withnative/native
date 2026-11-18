//! Authoring evidence under the same transaction and visibility as creation.
use super::*;
use crate::authorization::Capability;
use crate::mcp::tools::lifecycle::{SourceBasisInput, SOURCE_BASIS_FORMAT};
use sqlx::{Sqlite, SqliteConnection, Transaction};

pub(super) async fn resolve(
    tx: &mut Transaction<'_, Sqlite>,
    actor: &str,
    input: Option<&Value>,
) -> Result<Option<Value>> {
    resolve_on(tx, actor, input, "create_record").await
}

pub(super) fn validate_input(input: Option<&Value>, tool: &str) -> Result<()> {
    if let Some(input) = input {
        parse_sources(input, tool)?;
    }
    Ok(())
}

fn parse_sources(input: &Value, tool: &str) -> Result<Vec<SourceBasisInput>> {
    let sources: Vec<SourceBasisInput> = serde_json::from_value(input.clone())
        .map_err(|_| Error::engine(format!("{tool}: sources must be an array of record ids or {{record_id, reason, role?, revision_event_id?}}")))?;
    if sources.len() > crate::authoring::MAX_SAVE_ACCOUNT_SOURCES {
        return Err(Error::engine(format!("{tool}: too many sources")));
    }
    let mut seen = std::collections::BTreeSet::new();
    for source in &sources {
        let (id, reason, role, supplied) = source_parts(source);
        crate::authoring::validate_identifier(tool, id, "sources.record_id")?;
        if !seen.insert(id) {
            return Err(Error::engine(format!("{tool}: duplicate source record_id")));
        }
        for (key, value) in [("reason", reason), ("role", role)] {
            if let Some(value) = value {
                crate::authoring::validate_prose(tool, value, key)?;
            }
        }
        if let Some(revision) = supplied {
            crate::authoring::validate_identifier(tool, revision, "revision_event_id")?;
        }
    }
    Ok(sources)
}

fn source_parts(source: &SourceBasisInput) -> (&str, Option<&str>, Option<&str>, Option<&str>) {
    match source {
        SourceBasisInput::Bare(id) => (id, None, None, None),
        SourceBasisInput::Object(o) => (
            &o.record_id,
            Some(&o.reason),
            o.role.as_deref(),
            o.revision_event_id.as_deref(),
        ),
    }
}

pub(super) async fn resolve_on(
    tx: &mut SqliteConnection,
    actor: &str,
    input: Option<&Value>,
    tool: &str,
) -> Result<Option<Value>> {
    let Some(input) = input else { return Ok(None) };
    let sources = parse_sources(input, tool)?;
    let mut stored = Vec::new();
    for (ordinal, source) in sources.iter().enumerate() {
        let (id, reason, role, supplied) = source_parts(source);
        kernel::kernel_require(tx, actor, id, Capability::View).await?;
        // Native and retained-v1 revision identities stay in their own namespace.
        // Bodyless creation is a real revision, as in v1's contribution contract.
        let revision: Option<String> = sqlx::query_scalar(r#"
            WITH revisions AS (
              SELECT seq,id FROM content_events WHERE record_id=?1 AND
                (type IN ('kernel.record_created.v1','kernel.record_created.v2','kernel.import_record_created.v1','kernel.import_state.v1','kernel.import_state_delta.v1') OR type='kernel.body_set.v1'
                 OR (type IN ('kernel.record_revised.v1','kernel.record_revised.v2') AND json_type(payload,'$.fields.body') IS NOT NULL))
              UNION ALL
              SELECT h.seq,CASE WHEN ?2=e.id THEN e.id ELSE h.source_id END FROM kernel_legacy_sql_events h JOIN content_events e ON e.seq=h.seq
                WHERE h.record_id=?1 AND h.source_stream='content_events' AND
                (h.event_type='record.created' OR (h.event_type='record.updated' AND json_type(e.payload,'$.legacy.payload.body') IS NOT NULL))
            ) SELECT id FROM revisions WHERE ?2 IS NULL OR id=?2 ORDER BY seq DESC LIMIT 1
        "#).bind(id).bind(supplied).fetch_optional(&mut *tx).await?;
        let revision = revision.ok_or_else(|| {
            Error::engine(format!(
                "{tool}: source revision is not a body revision of the cited record"
            ))
        })?;
        stored.push(json!({"ordinal":ordinal,"record_id":id,"revision_event_id":revision,
            "revision_supplied_by":if supplied.is_some(){"caller"}else{"engine"},"role":role,"reason":reason}));
    }
    Ok(Some(json!({"format":SOURCE_BASIS_FORMAT,"sources":stored})))
}
