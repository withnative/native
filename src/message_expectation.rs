//! Live reconciliation for the sender-declared Message expectation axis.
//!
//! The declaration is stored as a governed open facet. Satisfaction is never a
//! mutable flag: this module recomputes it from durable recipient-authored
//! evidence at read time.

use std::collections::HashMap;

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
    validate_message_type(record_type.as_deref(), message_id)?;

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
    finish_expectation_derivation(
        source,
        message_id,
        recipient_id,
        portable_recipient_id,
        raw,
        filter_evidence_to_query_viewer,
    )
    .await
}

/// Shared record-type gate: missing sources and wrong-type sources fail
/// before any facet read. Both the scalar preload above and the batch loop
/// below call this, so error precedence has exactly one definition and no
/// mapping is duplicated.
fn validate_message_type(record_type: Option<&str>, message_id: &str) -> Result<()> {
    match record_type {
        None => Err(Error::engine(format!(
            "message expectation source {message_id} does not exist"
        ))),
        Some("Message") => Ok(()),
        Some(other) => Err(Error::engine(format!(
            "message expectation source {message_id} is {other}, not Message"
        ))),
    }
}

/// Live, request-local batch form of the scalar preload above: one recipient
/// binding lookup plus one set-wise record-type load and one set-wise
/// expectation-facet load (three constant statements total), then the shared
/// evaluator below per Message on the same transaction.
///
/// Only the three base preloads are set-wise. Evidence walks stay per-Message
/// scalar inside the shared evaluator, preserving execution order and error
/// behaviour exactly (including the eager `ack.or(reply)` shape). There is no
/// cross-call cache: every call re-reads its transaction snapshot.
///
/// The returned derivations align with the input order, with duplicates
/// repeated, so callers can zip them back onto their input.
pub(crate) async fn derive_message_expectation_states_in(
    tx: &mut Transaction<'_, Sqlite>,
    message_ids: &[String],
    recipient_id: &str,
) -> Result<Vec<MessageExpectationDerivation>> {
    if recipient_id.trim().is_empty() {
        return Err(Error::engine(
            "message expectation recipient_id must not be empty",
        ));
    }
    if message_ids.is_empty() {
        return Ok(Vec::new());
    }
    let portable_recipient_id: Option<String> = sqlx::query_scalar(
        "SELECT record_id FROM main.bindings
          WHERE system = 'account' AND identifier = ? AND is_canonical = 1
          ORDER BY record_id LIMIT 1",
    )
    .bind(recipient_id)
    .fetch_optional(&mut **tx)
    .await?;
    let portable_recipient_id = portable_recipient_id.as_deref().unwrap_or(recipient_id);

    let ids_json = serde_json::to_string(message_ids)?;
    let mut record_types: HashMap<String, String> = HashMap::with_capacity(message_ids.len());
    for row in sqlx::query(
        "SELECT id, type FROM main.records
          WHERE id IN (SELECT value FROM json_each(?))",
    )
    .bind(&ids_json)
    .fetch_all(&mut **tx)
    .await?
    {
        let id: String = row.try_get("id")?;
        let record_type: String = row.try_get("type")?;
        record_types.entry(id).or_insert(record_type);
    }
    let mut raw_facets: HashMap<String, String> = HashMap::with_capacity(message_ids.len());
    for row in sqlx::query(
        "SELECT record_id, value FROM main.facet_values
          WHERE record_id IN (SELECT value FROM json_each(?)) AND key = ?",
    )
    .bind(&ids_json)
    .bind(EXPECTATION_FACET_KEY)
    .fetch_all(&mut **tx)
    .await?
    {
        let record_id: String = row.try_get("record_id")?;
        let value: Option<String> = row.try_get("value")?;
        if let Some(value) = value {
            raw_facets.entry(record_id).or_insert(value);
        }
    }

    let mut source = ExpectationRead::Live(tx);
    let mut derived_by_id: HashMap<String, MessageExpectationDerivation> =
        HashMap::with_capacity(message_ids.len());
    for message_id in message_ids {
        if !derived_by_id.contains_key(message_id) {
            validate_message_type(record_types.get(message_id).map(String::as_str), message_id)?;
            let derived = finish_expectation_derivation(
                &mut source,
                message_id,
                recipient_id,
                portable_recipient_id,
                raw_facets.get(message_id).cloned(),
                false,
            )
            .await?;
            derived_by_id.insert(message_id.clone(), derived);
        }
    }
    Ok(message_ids
        .iter()
        .map(|message_id| {
            derived_by_id
                .get(message_id)
                .cloned()
                .expect("derived above for every input id")
        })
        .collect())
}

/// Shared evaluator for one Message: the absent/invalid/`none` early
/// returns and the evidence match. Both the scalar preload sequence above
/// and the set-wise batch preload converge here, so derivation semantics
/// have exactly one definition. Record-type gating lives in
/// [`validate_message_type`], which callers run before any facet read.
async fn finish_expectation_derivation(
    source: &mut ExpectationRead<'_, '_>,
    message_id: &str,
    recipient_id: &str,
    portable_recipient_id: &str,
    raw: Option<String>,
    filter_evidence_to_query_viewer: bool,
) -> Result<MessageExpectationDerivation> {
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

#[cfg(test)]
mod batch_preload_tests {
    use serde_json::json;

    use super::*;
    use crate::db::create_database;
    use crate::events::{FacetSetPayload, LinkAddedPayload};
    use crate::query::test_sqlite::SqliteTrace;
    use crate::store::{add_link_as, create_record, set_facet};

    const BOUND_ACCOUNT: &str = "acct:batch-recipient";
    const BOUND_PERSON: &str = "f7ec1000-0000-4000-8000-000000000001";
    const UNBOUND_ACCOUNT: &str = "acct:batch-unbound";
    const SENDER_PRINCIPAL: &str = "native/batch-sender";

    fn message_id(suffix: u32) -> String {
        format!("f7ec2000-0000-4000-8000-{suffix:012}")
    }

    async fn install_bound_person(db: &crate::db::Db) {
        create_record(
            db,
            json!({ "id": BOUND_PERSON, "type": "Entity", "kind": "person", "name": "Recipient" }),
        )
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO bindings(record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(BOUND_PERSON)
        .bind(BOUND_ACCOUNT)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn create_message(db: &crate::db::Db, id: &str) {
        create_record(
            db,
            json!({ "id": id, "type": "Message", "kind": "text", "name": id }),
        )
        .await
        .unwrap();
    }

    async fn set_expectation(db: &crate::db::Db, id: &str, value: &str) {
        set_facet(
            db,
            id,
            FacetSetPayload {
                key: EXPECTATION_FACET_KEY.into(),
                value: Some(value.into()),
                vocab_ref: None,
                as_of: None,
                observation_only: false,
            },
        )
        .await
        .unwrap();
    }

    async fn add_audience(db: &crate::db::Db, message_id: &str, principal: &str, source: &str) {
        sqlx::query(
            "INSERT INTO message_audiences(message_id, principal_id, source, grant_id, event_seq, created_at)
             VALUES (?, ?, ?, 'test-grant', 1, '2026-01-01T00:00:00Z')",
        )
        .bind(message_id)
        .bind(principal)
        .bind(source)
        .execute(db.write_pool())
        .await
        .unwrap();
    }

    async fn link_as(
        db: &crate::db::Db,
        source_id: &str,
        target_id: &str,
        relationship: &str,
        actor: &str,
    ) {
        add_link_as(
            db,
            LinkAddedPayload {
                id: None,
                source_id: source_id.into(),
                target_id: target_id.into(),
                relationship: relationship.into(),
                note: None,
            },
            Some(actor),
        )
        .await
        .unwrap();
    }

    /// Eleven Messages covering every derivation shape: absent and invalid
    /// facets (Unknown), `none` (NotRequired), open and satisfied `ack`,
    /// `reply` (open via missing sender audience, satisfied via audiences),
    /// `action` (open, satisfied via terminally completed WorkItem),
    /// `decision` (open, satisfied via decision Resolution).
    async fn seed_state_matrix(db: &crate::db::Db) -> Vec<String> {
        install_bound_person(db).await;
        let ids: Vec<String> = (0..11).map(message_id).collect();
        for id in &ids {
            create_message(db, id).await;
        }
        set_expectation(db, &ids[1], "bogus").await;
        set_expectation(db, &ids[2], "none").await;
        set_expectation(db, &ids[3], "ack").await;
        // ids[4]: satisfied ack.
        set_expectation(db, &ids[4], "ack").await;
        let ack_evidence = message_id(100);
        create_record(
            db,
            json!({ "id": ack_evidence, "type": "Message", "kind": "text",
                    "name": "ack evidence", "owner_id": BOUND_PERSON }),
        )
        .await
        .unwrap();
        link_as(db, &ack_evidence, &ids[4], "acknowledges", BOUND_ACCOUNT).await;
        // ids[5]: open reply (no sender audience, so no evidence walk).
        set_expectation(db, &ids[5], "reply").await;
        // ids[6]: satisfied reply.
        set_expectation(db, &ids[6], "reply").await;
        add_audience(db, &ids[6], SENDER_PRINCIPAL, "sender").await;
        let reply = message_id(101);
        create_record(
            db,
            json!({ "id": reply, "type": "Message", "kind": "text",
                    "name": "reply evidence", "owner_id": BOUND_PERSON }),
        )
        .await
        .unwrap();
        add_audience(db, &reply, SENDER_PRINCIPAL, "addressed_to").await;
        link_as(db, &reply, &ids[6], "reply_to", BOUND_ACCOUNT).await;
        // ids[7]: open action.
        set_expectation(db, &ids[7], "action").await;
        // ids[8]: satisfied action via terminally completed WorkItem.
        set_expectation(db, &ids[8], "action").await;
        let work = message_id(102);
        create_record(
            db,
            json!({ "id": work, "type": "WorkItem", "kind": "task",
                    "name": "completed work", "owner_id": BOUND_PERSON,
                    "lifecycle": "completed" }),
        )
        .await
        .unwrap();
        link_as(db, &work, &ids[8], "derived_from", BOUND_ACCOUNT).await;
        // ids[9]: open decision.
        set_expectation(db, &ids[9], "decision").await;
        // ids[10]: satisfied decision via decision Resolution.
        set_expectation(db, &ids[10], "decision").await;
        let resolution = message_id(103);
        create_record(
            db,
            json!({ "id": resolution, "type": "Resolution", "kind": "decision",
                    "name": "governed choice", "owner_id": BOUND_PERSON }),
        )
        .await
        .unwrap();
        link_as(db, &resolution, &ids[10], "derived_from", BOUND_ACCOUNT).await;
        ids
    }

    async fn scalar_all(
        tx: &mut Transaction<'_, Sqlite>,
        ids: &[String],
        recipient: &str,
    ) -> Vec<MessageExpectationDerivation> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            out.push(
                derive_message_expectation_state_in(tx, id, recipient)
                    .await
                    .unwrap(),
            );
        }
        out
    }

    /// The base preload (binding, types, facets) is constant while the scalar
    /// control stays linear: 24 statements at 8 Messages, 192 at 64.
    /// Seeding stays outside the measured scope; both sides derive on the
    /// same transaction shape. No timing assertions.
    #[tokio::test]
    async fn batch_base_preload_statement_count_is_constant() {
        async fn seed_absent_none(db: &crate::db::Db, count: usize) -> Vec<String> {
            let mut ids = Vec::with_capacity(count);
            for index in 0..count {
                let id = format!("f7ec3000-0000-4000-8000-{index:012}");
                create_message(db, &id).await;
                if index % 2 == 1 {
                    set_expectation(db, &id, "none").await;
                }
                ids.push(id);
            }
            ids
        }
        async fn traced_scalar(db: &crate::db::Db, ids: &[String]) -> usize {
            let mut tx = db.write_pool().begin().await.unwrap();
            let trace = SqliteTrace::install(&mut tx).await.unwrap();
            for id in ids {
                derive_message_expectation_state_in(&mut tx, id, UNBOUND_ACCOUNT)
                    .await
                    .unwrap();
            }
            let work = trace.finish(&mut tx).await.unwrap();
            tx.rollback().await.unwrap();
            assert_eq!(work.internal_statements, 0);
            work.statements
        }
        async fn traced_batch(db: &crate::db::Db, ids: &[String]) -> usize {
            let mut tx = db.write_pool().begin().await.unwrap();
            let trace = SqliteTrace::install(&mut tx).await.unwrap();
            derive_message_expectation_states_in(&mut tx, ids, UNBOUND_ACCOUNT)
                .await
                .unwrap();
            let work = trace.finish(&mut tx).await.unwrap();
            tx.rollback().await.unwrap();
            assert_eq!(work.internal_statements, 0);
            work.statements
        }

        let small_db = create_database(":memory:").await.unwrap();
        let small_ids = seed_absent_none(&small_db, 8).await;
        let large_db = create_database(":memory:").await.unwrap();
        let large_ids = seed_absent_none(&large_db, 64).await;
        let small_scalar = traced_scalar(&small_db, &small_ids).await;
        let large_scalar = traced_scalar(&large_db, &large_ids).await;
        let small_batch = traced_batch(&small_db, &small_ids).await;
        let large_batch = traced_batch(&large_db, &large_ids).await;
        eprintln!(
            "expectation preload statements: scalar small(8)={small_scalar} large(64)={large_scalar}; \
             batch small(8)={small_batch} large(64)={large_batch}"
        );
        assert_eq!(small_scalar, 24, "scalar base is 3 statements per Message");
        assert_eq!(large_scalar, 192, "scalar base is 3 statements per Message");
        assert_eq!(small_batch, 3, "batch base is binding, types, facets");
        assert_eq!(
            large_batch, small_batch,
            "batch base must not grow with Message count"
        );
        small_db.close().await;
        large_db.close().await;
    }

    /// Batch derivations equal scalar derivations across every expectation
    /// shape, for bound and unbound recipients, with duplicates repeated in
    /// input order, empty input, and identical error text for empty
    /// recipients, missing sources, and wrong-type sources.
    #[tokio::test]
    async fn batch_matches_scalar_across_states_callers_and_shapes() {
        let db = create_database(":memory:").await.unwrap();
        let ids = seed_state_matrix(&db).await;
        let mut tx = db.write_pool().begin().await.unwrap();

        let scalar_bound = scalar_all(&mut tx, &ids, BOUND_ACCOUNT).await;
        let batch_bound = derive_message_expectation_states_in(&mut tx, &ids, BOUND_ACCOUNT)
            .await
            .unwrap();
        assert_eq!(batch_bound, scalar_bound);

        // Pin the shape ladder itself, not just batch/scalar agreement.
        let states: Vec<MessageExpectationState> = scalar_bound.iter().map(|d| d.state).collect();
        use MessageExpectationState as State;
        assert_eq!(
            states,
            vec![
                State::Unknown,     // absent
                State::Unknown,     // invalid legacy value
                State::NotRequired, // none
                State::Open,        // ack, no evidence
                State::Satisfied,   // ack
                State::Open,        // reply, no sender audience
                State::Satisfied,   // reply
                State::Open,        // action, no work
                State::Satisfied,   // action
                State::Open,        // decision, no resolution
                State::Satisfied,   // decision
            ]
        );
        assert_eq!(scalar_bound[0].expectation, None);
        assert_eq!(scalar_bound[1].expectation, None);
        assert_eq!(scalar_bound[2].expectation.as_deref(), Some("none"));
        assert_eq!(
            scalar_bound[4].evidence.as_ref().unwrap().kind,
            MessageExpectationEvidenceKind::Acknowledgement
        );
        assert_eq!(
            scalar_bound[6].evidence.as_ref().unwrap().kind,
            MessageExpectationEvidenceKind::Reply
        );
        assert_eq!(
            scalar_bound[8].evidence.as_ref().unwrap().kind,
            MessageExpectationEvidenceKind::CompletedWorkItem
        );
        assert_eq!(
            scalar_bound[10].evidence.as_ref().unwrap().kind,
            MessageExpectationEvidenceKind::Decision
        );

        // Unbound callers keep the single-id fallback on both paths: the
        // recipient-owned evidence no longer matches, so the satisfied ack
        // reads Open here, identically on both sides.
        let scalar_unbound = scalar_all(&mut tx, &ids, UNBOUND_ACCOUNT).await;
        let batch_unbound = derive_message_expectation_states_in(&mut tx, &ids, UNBOUND_ACCOUNT)
            .await
            .unwrap();
        assert_eq!(batch_unbound, scalar_unbound);
        assert_eq!(scalar_unbound[4].state, State::Open);

        // Duplicates repeat in input order; empty input yields empty output.
        let dup_ids = vec![ids[4].clone(), ids[0].clone(), ids[4].clone()];
        let batch_dup = derive_message_expectation_states_in(&mut tx, &dup_ids, BOUND_ACCOUNT)
            .await
            .unwrap();
        assert_eq!(
            batch_dup,
            vec![
                scalar_bound[4].clone(),
                scalar_bound[0].clone(),
                scalar_bound[4].clone()
            ]
        );
        let empty = derive_message_expectation_states_in(&mut tx, &[], BOUND_ACCOUNT)
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Error text matches the scalar path exactly.
        let scalar_empty = derive_message_expectation_state_in(&mut tx, &ids[0], "  ")
            .await
            .unwrap_err()
            .to_string();
        let batch_empty = derive_message_expectation_states_in(&mut tx, &ids[0..1], "  ")
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(batch_empty, scalar_empty);
        let missing = message_id(999);
        let scalar_missing = derive_message_expectation_state_in(&mut tx, &missing, BOUND_ACCOUNT)
            .await
            .unwrap_err()
            .to_string();
        let batch_missing = derive_message_expectation_states_in(
            &mut tx,
            std::slice::from_ref(&missing),
            BOUND_ACCOUNT,
        )
        .await
        .unwrap_err()
        .to_string();
        assert_eq!(batch_missing, scalar_missing);
        let scalar_wrong =
            derive_message_expectation_state_in(&mut tx, BOUND_PERSON, BOUND_ACCOUNT)
                .await
                .unwrap_err()
                .to_string();
        let batch_wrong =
            derive_message_expectation_states_in(&mut tx, &[BOUND_PERSON.into()], BOUND_ACCOUNT)
                .await
                .unwrap_err()
                .to_string();
        assert_eq!(batch_wrong, scalar_wrong);

        tx.rollback().await.unwrap();
        db.close().await;
    }

    /// Each batch call re-reads its transaction: a facet change and a later
    /// recipient binding are both visible to the next call, so there is no
    /// cross-call cache to go stale.
    #[tokio::test]
    async fn batch_reflects_facet_and_binding_changes_on_new_call() {
        let db = create_database(":memory:").await.unwrap();
        install_bound_person(&db).await;
        let target = message_id(500);
        create_message(&db, &target).await;
        let evidence = message_id(501);
        create_record(
            &db,
            json!({ "id": evidence, "type": "Message", "kind": "text",
                    "name": "ack evidence", "owner_id": BOUND_PERSON }),
        )
        .await
        .unwrap();

        // Absent facet reads Unknown through the batch path.
        let mut tx = db.write_pool().begin().await.unwrap();
        let first = derive_message_expectation_states_in(
            &mut tx,
            std::slice::from_ref(&target),
            BOUND_ACCOUNT,
        )
        .await
        .unwrap();
        assert_eq!(first[0].state, MessageExpectationState::Unknown);
        tx.rollback().await.unwrap();

        // Declaring `ack` plus recipient-authored evidence moves a fresh call
        // to Satisfied.
        set_expectation(&db, &target, "ack").await;
        link_as(&db, &evidence, &target, "acknowledges", BOUND_ACCOUNT).await;
        let mut tx = db.write_pool().begin().await.unwrap();
        let second = derive_message_expectation_states_in(
            &mut tx,
            std::slice::from_ref(&target),
            BOUND_ACCOUNT,
        )
        .await
        .unwrap();
        assert_eq!(second[0].state, MessageExpectationState::Satisfied);
        // The scalar path agrees on the same snapshot.
        let scalar = derive_message_expectation_state_in(&mut tx, &target, BOUND_ACCOUNT)
            .await
            .unwrap();
        assert_eq!(second[0], scalar);
        tx.rollback().await.unwrap();

        // A dedicated person record owns this phase's evidence, so the
        // initially unbound account sees Open; binding it to the owning
        // person flips a fresh batch call to Satisfied. (One account binding
        // per person record, so the shared fixture owner cannot be reused.)
        let fresh_person = message_id(502);
        create_record(
            &db,
            json!({ "id": fresh_person, "type": "Entity", "kind": "person", "name": "Fresh" }),
        )
        .await
        .unwrap();
        let fresh_target = message_id(503);
        create_message(&db, &fresh_target).await;
        set_expectation(&db, &fresh_target, "ack").await;
        let fresh_evidence = message_id(504);
        create_record(
            &db,
            json!({ "id": fresh_evidence, "type": "Message", "kind": "text",
                    "name": "fresh ack evidence", "owner_id": fresh_person }),
        )
        .await
        .unwrap();
        link_as(
            &db,
            &fresh_evidence,
            &fresh_target,
            "acknowledges",
            UNBOUND_ACCOUNT,
        )
        .await;
        let mut tx = db.write_pool().begin().await.unwrap();
        let unbound = derive_message_expectation_states_in(
            &mut tx,
            std::slice::from_ref(&fresh_target),
            UNBOUND_ACCOUNT,
        )
        .await
        .unwrap();
        assert_eq!(unbound[0].state, MessageExpectationState::Open);
        tx.rollback().await.unwrap();
        sqlx::query(
            "INSERT INTO bindings(record_id, system, identifier, is_canonical)
             VALUES (?, 'account', ?, 1)",
        )
        .bind(&fresh_person)
        .bind(UNBOUND_ACCOUNT)
        .execute(db.write_pool())
        .await
        .unwrap();
        let mut tx = db.write_pool().begin().await.unwrap();
        let rebound = derive_message_expectation_states_in(
            &mut tx,
            std::slice::from_ref(&fresh_target),
            UNBOUND_ACCOUNT,
        )
        .await
        .unwrap();
        assert_eq!(rebound[0].state, MessageExpectationState::Satisfied);
        tx.rollback().await.unwrap();
        db.close().await;
    }

    /// Missing and wrong-type sources fail before any facet read on the
    /// scalar path: binding plus record-type lookup only, two statements.
    /// This pins the original preload/error order by statement count, not
    /// just by error text.
    #[tokio::test]
    async fn scalar_error_path_reads_binding_and_type_only() {
        let db = create_database(":memory:").await.unwrap();
        install_bound_person(&db).await;
        let missing = message_id(600);
        for (id, expected_fragment) in [
            (missing.as_str(), "does not exist"),
            (BOUND_PERSON, "not Message"),
        ] {
            let mut tx = db.write_pool().begin().await.unwrap();
            let trace = SqliteTrace::install(&mut tx).await.unwrap();
            let error = derive_message_expectation_state_in(&mut tx, id, BOUND_ACCOUNT)
                .await
                .unwrap_err()
                .to_string();
            let work = trace.finish(&mut tx).await.unwrap();
            tx.rollback().await.unwrap();
            assert!(
                error.contains(expected_fragment),
                "unexpected error text: {error}"
            );
            assert_eq!(work.internal_statements, 0);
            assert_eq!(
                work.statements, 2,
                "error path must stop after binding and record-type reads"
            );
        }
        db.close().await;
    }
}
