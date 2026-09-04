//! Live reconciliation for the sender-declared Message expectation axis.
//!
//! The declaration is stored as a governed open facet. Satisfaction is never a
//! mutable flag: this module recomputes it from durable recipient-authored
//! evidence at read time.

use serde::Serialize;
use sqlx::{Row, Sqlite, Transaction};

use crate::db::Db;
use crate::error::{Error, Result};
use crate::generated::kinds::CoreKind;
use crate::query::{cascade, lens::ReadLens};

pub const EXPECTATION_FACET_KEY: &str = "expectation";
pub const EXPECTATION_VOCABULARY: &str = "message-expectation";
pub const EXPECTATION_VOCABULARY_ID: &str = "voc:message-expectation";
pub const EXPECTATION_DERIVATION_VERSION: &str = "native.message.expectation-state.v1";
pub const EXPECTATION_VALUES: [&str; 5] = ["none", "ack", "reply", "action", "decision"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageExpectationState {
    Unknown,
    NotRequired,
    Open,
    Satisfied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageExpectationEvidenceKind {
    Acknowledgement,
    Reply,
    CompletedWorkItem,
    Decision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageExpectationEvidence {
    pub kind: MessageExpectationEvidenceKind,
    pub record_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MessageExpectationDerivation {
    pub format: &'static str,
    pub message_id: String,
    pub recipient_id: String,
    /// The sender declaration. `None` means historical absence or invalid
    /// legacy data; it never means the affirmative value `none`.
    pub expectation: Option<String>,
    pub state: MessageExpectationState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<MessageExpectationEvidence>,
}

struct EvidenceRow {
    id: String,
    owner_id: Option<String>,
    kind: Option<String>,
}

struct WorkEvidenceRow {
    id: String,
    kind: Option<String>,
    home_id: Option<String>,
    owner_id: Option<String>,
    lifecycle: Option<String>,
}

enum ExpectationRead<'a, 'db> {
    Lens(&'a ReadLens<'db>),
    Live(&'a mut Transaction<'db, Sqlite>),
}

impl ExpectationRead<'_, '_> {
    async fn first_text(&mut self, sql: &str, first: &str) -> Result<Option<String>> {
        match self {
            Self::Lens(lens) => Ok(sqlx::query_scalar::<_, String>(sql)
                .bind(first)
                .fetch_optional(lens.projection().snapshot_pool())
                .await?),
            Self::Live(tx) => Ok(sqlx::query_scalar::<_, String>(sql)
                .bind(first)
                .fetch_optional(&mut ***tx)
                .await?),
        }
    }

    async fn exists_two(&mut self, sql: &str, first: &str, second: &str) -> Result<bool> {
        let query = sqlx::query_scalar(sql).bind(first).bind(second);
        match self {
            Self::Lens(lens) => Ok(query.fetch_one(lens.projection().snapshot_pool()).await?),
            Self::Live(tx) => Ok(query.fetch_one(&mut ***tx).await?),
        }
    }

    async fn recipient_binding(&mut self, recipient_id: &str) -> Result<Option<String>> {
        let sql = "SELECT record_id FROM main.bindings
          WHERE system = 'account' AND identifier = ? AND is_canonical = 1
          ORDER BY record_id LIMIT 1";
        match self {
            Self::Lens(lens) => Ok(sqlx::query_scalar(sql)
                .bind(recipient_id)
                .fetch_optional(lens.meta().shared_pool())
                .await?),
            Self::Live(tx) => Ok(sqlx::query_scalar(sql)
                .bind(recipient_id)
                .fetch_optional(&mut ***tx)
                .await?),
        }
    }

    async fn evidence_rows(
        &mut self,
        message_id: &str,
        relationship: &str,
        record_type: Option<&str>,
        link_order: bool,
        filter_to_query_viewer: bool,
    ) -> Result<Vec<EvidenceRow>> {
        let type_clause = record_type.map_or("", |_| "AND r.type = ?");
        let visibility_join = if filter_to_query_viewer {
            "JOIN temp._query_sql_visible_records evidence_visible ON evidence_visible.id = r.id"
        } else {
            ""
        };
        let order = if link_order {
            "l.created_at, l.id"
        } else {
            "r.created_at, r.id"
        };
        let sql = format!(
            "SELECT r.id, r.owner_id, r.kind
               FROM main.links l JOIN main.records r ON r.id = l.source_id
               {visibility_join}
               WHERE l.target_id = ? AND l.relationship = ? {type_clause}
              ORDER BY {order}"
        );
        let mut query = sqlx::query(&sql).bind(message_id).bind(relationship);
        if let Some(record_type) = record_type {
            query = query.bind(record_type);
        }
        let rows = match self {
            Self::Lens(lens) => query.fetch_all(lens.projection().snapshot_pool()).await?,
            Self::Live(tx) => query.fetch_all(&mut ***tx).await?,
        };
        rows.into_iter()
            .map(|row| {
                Ok(EvidenceRow {
                    id: row.try_get("id")?,
                    owner_id: row.try_get("owner_id")?,
                    kind: row.try_get("kind")?,
                })
            })
            .collect()
    }

    async fn work_rows(
        &mut self,
        message_id: &str,
        filter_to_query_viewer: bool,
    ) -> Result<Vec<WorkEvidenceRow>> {
        let visibility_join = if filter_to_query_viewer {
            "JOIN temp._query_sql_visible_records evidence_visible ON evidence_visible.id = r.id"
        } else {
            ""
        };
        let sql = format!(
            "SELECT r.id, r.kind, r.home_id, r.owner_id, r.lifecycle
           FROM main.links l JOIN main.records r ON r.id = l.source_id
           {visibility_join}
          WHERE l.target_id = ? AND l.relationship = 'derived_from'
            AND r.type = 'WorkItem'
          ORDER BY r.created_at, r.id"
        );
        let rows = match self {
            Self::Lens(lens) => {
                sqlx::query(&sql)
                    .bind(message_id)
                    .fetch_all(lens.projection().snapshot_pool())
                    .await?
            }
            Self::Live(tx) => {
                sqlx::query(&sql)
                    .bind(message_id)
                    .fetch_all(&mut ***tx)
                    .await?
            }
        };
        rows.into_iter()
            .map(|row| {
                Ok(WorkEvidenceRow {
                    id: row.try_get("id")?,
                    kind: row.try_get("kind")?,
                    home_id: row.try_get("home_id")?,
                    owner_id: row.try_get("owner_id")?,
                    lifecycle: row.try_get("lifecycle")?,
                })
            })
            .collect()
    }

    async fn schema_rows(&mut self) -> Result<Vec<cascade::SchemaConfigRow>> {
        match self {
            Self::Lens(lens) => {
                cascade::schema_config_rows_in_pool(lens.meta().snapshot_pool(), None).await
            }
            Self::Live(tx) => cascade::schema_config_rows_in(tx).await,
        }
    }

    /// Resolve a lifecycle token's terminality: id-or-name vocabulary
    /// reference, one hop through `alias_of`, canonical target required active
    /// and not itself an alias.
    ///
    /// KNOWN, ACCEPTED DUPLICATION of `query::lifecycle::LifecycleInterpreter`
    /// (audited 2026-08, record `ebded493`). The two agree today, value for
    /// value; this note exists so a later divergence is read as a bug rather
    /// than as two deliberately different rules.
    ///
    /// The seam is not reusable here as it stands, and generalising it is not
    /// a cheap change. `LifecycleInterpreter::load` takes `&Db` and reads
    /// `db.write_pool()` directly, twice, to amortize the schema and
    /// vocabulary tables across a consumer that classifies MANY rows in one
    /// pass. This resolver has the opposite shape on both axes: it runs
    /// against either a lens snapshot pool or an open write transaction
    /// (`Self::Lens` / `Self::Live`), and it answers about ONE token at a time
    /// inside expectation evaluation. Reusing the interpreter would mean
    /// generalising it over an executor — pushing `DomainStatementExecutor`
    /// plumbing through the read seam and through `VocabularyIndex::load` —
    /// and then paying a full vocabulary table scan per expectation, where a
    /// single indexed lookup is what is wanted. That is transaction plumbing
    /// and a performance regression bought for no behaviour change.
    ///
    /// Revisit if either side's semantics move, or if the interpreter grows an
    /// executor-generic constructor for another reason: at that point the join
    /// below should be deleted in favour of it.
    async fn terminality(&mut self, designator: &str, lifecycle: &str) -> Result<Option<String>> {
        let sql = "SELECT COALESCE(c.terminality, v.terminality)
               FROM main.vocabularies vocabulary
               JOIN main.vocabulary_values v ON v.vocabulary_id = vocabulary.id
               LEFT JOIN main.vocabulary_values c ON c.id = v.alias_of
              WHERE (vocabulary.id = ? OR vocabulary.name = ?)
                AND v.value = ?
                AND ((v.alias_of IS NULL AND v.status = 'active')
                  OR (v.alias_of IS NOT NULL AND c.status = 'active' AND c.alias_of IS NULL))
              ORDER BY v.id LIMIT 1";
        let query = sqlx::query_scalar(sql)
            .bind(designator)
            .bind(designator)
            .bind(lifecycle);
        match self {
            Self::Lens(lens) => Ok(query
                .fetch_optional(lens.meta().shared_pool())
                .await?
                .flatten()),
            Self::Live(tx) => Ok(query.fetch_optional(&mut ***tx).await?.flatten()),
        }
    }

    async fn kind_resolution(
        &mut self,
        record_type: &str,
        kind: &str,
    ) -> Result<crate::meta::kind::KindResolution> {
        match self {
            Self::Lens(lens) => {
                crate::meta::kind::resolve_in_pool(lens.meta().snapshot_pool(), record_type, kind)
                    .await
            }
            Self::Live(tx) => crate::meta::kind::resolve_on(tx, record_type, kind).await,
        }
    }

    async fn authored_by(&mut self, record_id: &str, actor: &str) -> Result<bool> {
        let max_seq = match self {
            Self::Lens(lens) => lens
                .temporal()
                .map(|temporal| temporal.resolved_content_seq)
                .unwrap_or(i64::MAX),
            Self::Live(_) => i64::MAX,
        };
        let query = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM main.content_events
              WHERE record_id = ? AND type = 'record.created' AND actor = ? AND seq <= ?)",
        )
        .bind(record_id)
        .bind(actor)
        .bind(max_seq);
        match self {
            Self::Lens(lens) => Ok(query.fetch_one(lens.content_log().snapshot_pool()).await?),
            Self::Live(tx) => Ok(query.fetch_one(&mut ***tx).await?),
        }
    }

    async fn relationship_authored_by(
        &mut self,
        source_id: &str,
        target_id: &str,
        relationship: &str,
        actor: &str,
    ) -> Result<bool> {
        let max_seq = match self {
            Self::Lens(lens) => lens
                .temporal()
                .map(|temporal| temporal.resolved_content_seq)
                .unwrap_or(i64::MAX),
            Self::Live(_) => i64::MAX,
        };
        let query = sqlx::query(
            "SELECT type, actor FROM main.content_events
              WHERE record_id = ? AND type IN ('link.added', 'link.removed')
                AND json_extract(payload, '$.source_id') = ?
                AND json_extract(payload, '$.target_id') = ?
                AND json_extract(payload, '$.relationship') = ? AND seq <= ?
              ORDER BY seq DESC LIMIT 1",
        )
        .bind(source_id)
        .bind(source_id)
        .bind(target_id)
        .bind(relationship)
        .bind(max_seq);
        let latest = match self {
            Self::Lens(lens) => {
                query
                    .fetch_optional(lens.content_log().snapshot_pool())
                    .await?
            }
            Self::Live(tx) => query.fetch_optional(&mut ***tx).await?,
        };
        let Some(latest) = latest else {
            return Ok(false);
        };
        Ok(latest.try_get::<String, _>("type")? == "link.added"
            && latest.try_get::<Option<String>, _>("actor")?.as_deref() == Some(actor))
    }
}

/// Derive against the live database.
pub async fn derive_message_expectation_state(
    db: &Db,
    message_id: &str,
    recipient_id: &str,
) -> Result<MessageExpectationDerivation> {
    derive_message_expectation_state_with_lens(&ReadLens::live(db), message_id, recipient_id).await
}

/// Derive against an explicit content lens while retaining live governance.
/// This is what an `as_of` record read uses: content evidence is pinned to the
/// requested prefix, while vocabularies and shape meaning remain live just as
/// they do for every other historical structured read.
pub(crate) async fn derive_message_expectation_state_with_lens(
    lens: &ReadLens<'_>,
    message_id: &str,
    recipient_id: &str,
) -> Result<MessageExpectationDerivation> {
    derive_message_expectation_state_from(
        &mut ExpectationRead::Lens(lens),
        message_id,
        recipient_id,
        false,
    )
    .await
}

pub(crate) async fn derive_message_expectation_state_in(
    tx: &mut Transaction<'_, Sqlite>,
    message_id: &str,
    recipient_id: &str,
) -> Result<MessageExpectationDerivation> {
    derive_message_expectation_state_from(
        &mut ExpectationRead::Live(tx),
        message_id,
        recipient_id,
        false,
    )
    .await
}

/// Derive inside one `query_sql` transaction while admitting only evidence in
/// that transaction's audited `_query_sql_visible_records` lens. This is the
/// negative-state seam used by caller-relative logical relations; it
/// deliberately returns no evidence details of its own.
pub(crate) async fn derive_message_expectation_state_for_viewer_in(
    tx: &mut Transaction<'_, Sqlite>,
    message_id: &str,
    recipient_id: &str,
) -> Result<MessageExpectationDerivation> {
    derive_message_expectation_state_from(
        &mut ExpectationRead::Live(tx),
        message_id,
        recipient_id,
        true,
    )
    .await
}

async fn derive_message_expectation_state_from(
    source: &mut ExpectationRead<'_, '_>,
    message_id: &str,
    recipient_id: &str,
    filter_evidence_to_query_viewer: bool,
) -> Result<MessageExpectationDerivation> {
    if recipient_id.trim().is_empty() {
        return Err(Error::engine(
            "message expectation recipient_id must not be empty",
        ));
    }
    // Authorization separates the caller's host credential from the portable
    // person record that owns their authored records. Resolve both sides here:
    // ownership evidence is compared to the portable id, while event
    // provenance is compared to the credential stamped on the content log.
    // Legacy/unbound callers retain the former single-id behaviour.
    let portable_recipient_id = source.recipient_binding(recipient_id).await?;
    let portable_recipient_id = portable_recipient_id.as_deref().unwrap_or(recipient_id);

    let record_type = source
        .first_text("SELECT type FROM main.records WHERE id = ?", message_id)
        .await?;
    match record_type.as_deref() {
        None => {
            return Err(Error::engine(format!(
                "message expectation source {message_id} does not exist"
            )))
        }
        Some("Message") => {}
        Some(other) => {
            return Err(Error::engine(format!(
                "message expectation source {message_id} is {other}, not Message"
            )))
        }
    }

    let raw = match source {
        ExpectationRead::Lens(lens) => sqlx::query_scalar::<_, Option<String>>(
            "SELECT value FROM main.facet_values WHERE record_id = ? AND key = ?",
        )
        .bind(message_id)
        .bind(EXPECTATION_FACET_KEY)
        .fetch_optional(lens.projection().snapshot_pool())
        .await?
        .flatten(),
        ExpectationRead::Live(tx) => sqlx::query_scalar::<_, Option<String>>(
            "SELECT value FROM main.facet_values WHERE record_id = ? AND key = ?",
        )
        .bind(message_id)
        .bind(EXPECTATION_FACET_KEY)
        .fetch_optional(&mut ***tx)
        .await?
        .flatten(),
    };
    let declared = raw
        .as_deref()
        .filter(|value| EXPECTATION_VALUES.contains(value));

    let mut result = MessageExpectationDerivation {
        format: EXPECTATION_DERIVATION_VERSION,
        message_id: message_id.to_owned(),
        recipient_id: recipient_id.to_owned(),
        expectation: declared.map(str::to_owned),
        state: MessageExpectationState::Unknown,
        evidence: None,
    };
    let Some(expectation) = declared else {
        return Ok(result);
    };
    if expectation == "none" {
        result.state = MessageExpectationState::NotRequired;
        return Ok(result);
    }

    let evidence = match expectation {
        "ack" => explicit_acknowledgement(
            source,
            message_id,
            portable_recipient_id,
            recipient_id,
            filter_evidence_to_query_viewer,
        )
        .await?
        .or(reply(
            source,
            message_id,
            portable_recipient_id,
            recipient_id,
            filter_evidence_to_query_viewer,
        )
        .await?),
        "reply" => {
            reply(
                source,
                message_id,
                portable_recipient_id,
                recipient_id,
                filter_evidence_to_query_viewer,
            )
            .await?
        }
        "action" => {
            completed_work(
                source,
                message_id,
                portable_recipient_id,
                recipient_id,
                filter_evidence_to_query_viewer,
            )
            .await?
        }
        "decision" => {
            decision(
                source,
                message_id,
                portable_recipient_id,
                recipient_id,
                filter_evidence_to_query_viewer,
            )
            .await?
        }
        _ => unreachable!("expectation vocabulary checked above"),
    };
    result.state = if evidence.is_some() {
        MessageExpectationState::Satisfied
    } else {
        MessageExpectationState::Open
    };
    result.evidence = evidence;
    Ok(result)
}

async fn explicit_acknowledgement(
    source: &mut ExpectationRead<'_, '_>,
    message_id: &str,
    recipient_owner_id: &str,
    recipient_actor: &str,
    filter_evidence_to_query_viewer: bool,
) -> Result<Option<MessageExpectationEvidence>> {
    let rows = source
        .evidence_rows(
            message_id,
            "acknowledges",
            None,
            true,
            filter_evidence_to_query_viewer,
        )
        .await?;
    for row in rows {
        if authored_by_recipient(
            source,
            &row.id,
            row.owner_id.as_deref(),
            recipient_owner_id,
            recipient_actor,
        )
        .await?
            && relationship_authored_by_recipient(
                source,
                &row.id,
                message_id,
                "acknowledges",
                recipient_actor,
            )
            .await?
        {
            return Ok(Some(MessageExpectationEvidence {
                kind: MessageExpectationEvidenceKind::Acknowledgement,
                record_id: row.id,
            }));
        }
    }
    Ok(None)
}

async fn reply(
    source: &mut ExpectationRead<'_, '_>,
    message_id: &str,
    recipient_owner_id: &str,
    recipient_actor: &str,
    filter_evidence_to_query_viewer: bool,
) -> Result<Option<MessageExpectationEvidence>> {
    let original_sender = source
        .first_text(
            "SELECT principal_id FROM main.message_audiences
              WHERE message_id = ? AND source = 'sender'
              ORDER BY event_seq LIMIT 1",
            message_id,
        )
        .await?;
    let Some(original_sender) = original_sender else {
        return Ok(None);
    };
    let rows = source
        .evidence_rows(
            message_id,
            "reply_to",
            Some("Message"),
            false,
            filter_evidence_to_query_viewer,
        )
        .await?;
    for row in rows {
        let delivered_to_sender = source
            .exists_two(
                "SELECT EXISTS(SELECT 1 FROM main.message_audiences
                  WHERE message_id = ? AND principal_id = ? AND source = 'addressed_to')",
                &row.id,
                &original_sender,
            )
            .await?;
        if delivered_to_sender
            && authored_by_recipient(
                source,
                &row.id,
                row.owner_id.as_deref(),
                recipient_owner_id,
                recipient_actor,
            )
            .await?
            && relationship_authored_by_recipient(
                source,
                &row.id,
                message_id,
                "reply_to",
                recipient_actor,
            )
            .await?
        {
            return Ok(Some(MessageExpectationEvidence {
                kind: MessageExpectationEvidenceKind::Reply,
                record_id: row.id,
            }));
        }
    }
    Ok(None)
}

async fn completed_work(
    source: &mut ExpectationRead<'_, '_>,
    message_id: &str,
    recipient_owner_id: &str,
    recipient_actor: &str,
    filter_evidence_to_query_viewer: bool,
) -> Result<Option<MessageExpectationEvidence>> {
    let rows = source
        .work_rows(message_id, filter_evidence_to_query_viewer)
        .await?;
    let schema_rows = source.schema_rows().await?;
    for row in rows {
        if !authored_by_recipient(
            source,
            &row.id,
            row.owner_id.as_deref(),
            recipient_owner_id,
            recipient_actor,
        )
        .await?
        {
            continue;
        }
        if !relationship_authored_by_recipient(
            source,
            &row.id,
            message_id,
            "derived_from",
            recipient_actor,
        )
        .await?
        {
            continue;
        }
        let Some(lifecycle) = row.lifecycle.as_deref() else {
            continue;
        };
        let facets = cascade::facets_for_record_context(
            &schema_rows,
            "WorkItem",
            row.kind.as_deref(),
            row.home_id.as_deref(),
        );
        let governing = facets
            .get("lifecycle")
            .and_then(|shape| shape.get("vocab").or_else(|| shape.get("vocab_ref")))
            .and_then(serde_json::Value::as_str);
        let Some(governing) = governing else { continue };
        let designator = crate::meta::resolve_vocab_ref(governing);
        let terminality = source.terminality(designator, lifecycle).await?;
        if terminality.as_deref() == Some("terminal_positive") {
            return Ok(Some(MessageExpectationEvidence {
                kind: MessageExpectationEvidenceKind::CompletedWorkItem,
                record_id: row.id,
            }));
        }
    }
    Ok(None)
}

async fn decision(
    source: &mut ExpectationRead<'_, '_>,
    message_id: &str,
    recipient_owner_id: &str,
    recipient_actor: &str,
    filter_evidence_to_query_viewer: bool,
) -> Result<Option<MessageExpectationEvidence>> {
    let rows = source
        .evidence_rows(
            message_id,
            "derived_from",
            Some("Resolution"),
            false,
            filter_evidence_to_query_viewer,
        )
        .await?;
    for row in rows {
        if !authored_by_recipient(
            source,
            &row.id,
            row.owner_id.as_deref(),
            recipient_owner_id,
            recipient_actor,
        )
        .await?
        {
            continue;
        }
        if !relationship_authored_by_recipient(
            source,
            &row.id,
            message_id,
            "derived_from",
            recipient_actor,
        )
        .await?
        {
            continue;
        }
        let Some(kind) = row.kind.as_deref() else {
            continue;
        };
        let resolution = source.kind_resolution("Resolution", kind).await?;
        if CoreKind::ResolutionDecision.matches(&resolution) {
            return Ok(Some(MessageExpectationEvidence {
                kind: MessageExpectationEvidenceKind::Decision,
                record_id: row.id,
            }));
        }
    }
    Ok(None)
}

async fn authored_by_recipient(
    source: &mut ExpectationRead<'_, '_>,
    record_id: &str,
    owner_id: Option<&str>,
    recipient_owner_id: &str,
    recipient_actor: &str,
) -> Result<bool> {
    if let Some(owner_id) = owner_id {
        return Ok(owner_id == recipient_owner_id);
    }
    source.authored_by(record_id, recipient_actor).await
}

/// Verify authorship of the current relationship assertion itself. Link rows
/// do not carry actor provenance, so consult the authoritative event stream and
/// take the latest add/remove for this natural key. Callers only ask about a
/// currently projected live link; nevertheless, requiring the latest event to
/// be a recipient-authored add also fails closed on projection corruption.
async fn relationship_authored_by_recipient(
    source: &mut ExpectationRead<'_, '_>,
    source_id: &str,
    target_id: &str,
    relationship: &str,
    recipient_id: &str,
) -> Result<bool> {
    source
        .relationship_authored_by(source_id, target_id, relationship, recipient_id)
        .await
}

#[cfg(test)]
mod snapshot_tests {
    use serde_json::json;

    use super::*;
    use crate::db::create_database;
    use crate::events::{FacetSetPayload, LinkAddedPayload};
    use crate::store::{add_link_as, create_record, set_facet};

    const RECIPIENT_ID: &str = "e8bec700-0000-4000-8000-000000000001";
    const MESSAGE_ID: &str = "e8bec700-0000-4000-8000-000000000002";
    /// The acknowledging message record. Distinct from the "ack" expectation
    /// facet *value*, which is vocabulary and not an id.
    const ACK_ID: &str = "e8bec700-0000-4000-8000-000000000003";

    #[tokio::test]
    async fn expectation_evidence_stays_on_the_caller_snapshot() {
        let db = create_database(":memory:").await.unwrap();
        create_record(
            &db,
            json!({ "id": RECIPIENT_ID, "type": "Entity", "kind": "person", "name": "Recipient" }),
        )
        .await
        .unwrap();
        create_record(
            &db,
            json!({ "id": MESSAGE_ID, "type": "Message", "kind": "text", "name": "Message" }),
        )
        .await
        .unwrap();
        set_facet(
            &db,
            MESSAGE_ID,
            FacetSetPayload {
                key: EXPECTATION_FACET_KEY.into(),
                value: Some("ack".into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();

        let mut snapshot = db.write_pool().begin().await.unwrap();
        let before = derive_message_expectation_state_in(&mut snapshot, MESSAGE_ID, RECIPIENT_ID)
            .await
            .unwrap();
        assert_eq!(before.state, MessageExpectationState::Open);

        create_record(
            &db,
            json!({
                "id": ACK_ID,
                "type": "Message",
                "kind": "text",
                "name": "Acknowledgement",
                "owner_id": RECIPIENT_ID
            }),
        )
        .await
        .unwrap();
        add_link_as(
            &db,
            LinkAddedPayload {
                id: None,
                source_id: ACK_ID.into(),
                target_id: MESSAGE_ID.into(),
                relationship: "acknowledges".into(),
                note: None,
            },
            Some(RECIPIENT_ID),
        )
        .await
        .unwrap();

        let pinned = derive_message_expectation_state_in(&mut snapshot, MESSAGE_ID, RECIPIENT_ID)
            .await
            .unwrap();
        assert_eq!(pinned.state, MessageExpectationState::Open);
        snapshot.rollback().await.unwrap();

        let current = derive_message_expectation_state(&db, MESSAGE_ID, RECIPIENT_ID)
            .await
            .unwrap();
        assert_eq!(current.state, MessageExpectationState::Satisfied);
    }
}
