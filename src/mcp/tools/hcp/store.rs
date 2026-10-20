//! Native-backed storage for the HCP preference tools.
//!
//! Every read and write goes through the same handlers an ordinary MCP client
//! uses (`query_sql`, `create_record`, `update_record`, `archive_record`,
//! `resolve_suggestions`), invoked with the connected person's own `Caller`.
//! Nothing here consults a client grant or reaches around Native
//! authorization; the OAuth client id is stamped as an attribution facet only.
//!
//! Storage shape (decisions in the slice-1 PR):
//!
//! * One `Document/note` catalog record per person holds the definitions as a
//!   JSON body (`hcp.role = preference-catalog`).
//! * One `Resolution/preference` record per slug holds the ACTIVE value as the
//!   canonical JSON text of its body. Setting a value revises the same record
//!   in place; history keeps earlier values. An explicitly empty body means
//!   the record has no active value (a shell: nothing set yet, or the value
//!   was deleted) but may still hold pending suggestions.
//! * A suggestion is an `Annotation/suggestion` record linked `part_of` the
//!   preference record, whose body is the proposed value. Accepting it in
//!   Native revises the preference record's body, so the value becomes ACTIVE
//!   without any HCP-specific code.
//! * Deleting a preference clears its value and keeps the record, so pending
//!   suggestions stay attached; withdrawing a suggestion archives it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;

use crate::db::Db;
use crate::error::{Error, Result};
use crate::provenance::Channel;

use super::model::{Catalog, Definition, CATALOG_CONTRACT};
use super::native_block::{self, Accepted, Attribution, Origin, Via, Writer};
use crate::mcp::registry::Caller;

pub(super) const FACET_ROLE: &str = "hcp.role";
pub(super) const FACET_PERSON: &str = "hcp.person";
pub(super) const FACET_SLUG: &str = "hcp.slug";
pub(super) const FACET_VALUE_TYPE: &str = "hcp.value_type";
/// The id of the definition a record was written under. A record only counts
/// while that exact definition is active, so archiving a definition and later
/// re-creating its slug starts from an empty slate instead of resurrecting
/// old values.
pub(super) const FACET_DEFINITION: &str = "hcp.definition";
/// Marks a suggestion HCP authored as a whole-value proposal (the only kind
/// HCP re-anchors or replaces). Suggestions made in Native, such as span edits,
/// carry no such facet and keep their own preconditions untouched.
pub(super) const FACET_PROPOSAL: &str = "hcp.proposal";
pub(super) const FACET_CLIENT: &str = "hcp.client";
pub(super) const FACET_CORRELATION: &str = "hcp.correlation";
pub(super) const FACET_CONFIDENCE: &str = "hcp.confidence";
pub(super) const FACET_EVIDENCE: &str = "hcp.evidence";
const CATALOG_ROLE: &str = "preference-catalog";

/// Upper bound on the evidence object a client may attach to one value.
pub(super) const MAX_EVIDENCE_BYTES: usize = 16 * 1024;

/// Attributions read per value; a value with more is read from its newest.
const ATTRIBUTION_WINDOW: i64 = 100;
/// Account holder's name when Native shows no name for the person record.
const UNNAMED_PERSON: &str = "account holder";

pub(super) fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

#[derive(Clone, Debug)]
pub(super) struct CatalogRecord {
    pub id: String,
    pub digest: String,
    pub catalog: Catalog,
}

#[derive(Clone, Debug)]
pub(super) struct PrefRecord {
    pub id: String,
    pub slug: String,
    pub definition_id: String,
    pub body: String,
    pub updated_at: String,
    /// Only the targeted lookups return archived records.
    pub archived: bool,
    /// Confidence as last written by HCP. It describes the current body only
    /// when HCP wrote that body; `Origin::confidence` decides.
    pub confidence: Option<f64>,
    /// The `hcp.client` and `hcp.evidence` of HCP's last write. Like
    /// `confidence`, they describe the current body only when HCP wrote it.
    pub client: Option<String>,
    pub evidence: Option<String>,
}

impl PrefRecord {
    /// The record holds an accepted value (not just a pending suggestion).
    pub(super) fn has_value(&self) -> bool {
        !self.body.trim().is_empty()
    }

    pub(super) fn value(&self) -> Option<Value> {
        if self.has_value() {
            serde_json::from_str(&self.body).ok()
        } else {
            None
        }
    }
}

#[derive(Clone, Debug)]
pub(super) struct SuggestionRecord {
    pub id: String,
    pub slug: String,
    pub definition_id: String,
    pub body: String,
    pub updated_at: String,
    pub confidence: Option<f64>,
    /// HCP authored this as a whole-value proposal (see `FACET_PROPOSAL`).
    pub hcp_authored: bool,
    pub client: Option<String>,
    pub evidence: Option<String>,
}

impl SuggestionRecord {
    pub(super) fn value(&self) -> Option<Value> {
        serde_json::from_str(&self.body).ok()
    }
}

/// What the `native` block needs besides the record itself: who the caller is
/// (as Native names them to this caller) and each record's short reference.
#[derive(Clone, Debug, Default)]
pub(super) struct Context {
    /// The person record behind the caller's account, and its name.
    pub person_id: Option<String>,
    pub person_name: Option<String>,
    references: HashMap<String, Option<String>>,
}

impl Context {
    /// The `native` block and the `sourceType` for one value.
    pub(super) fn describe(
        &self,
        origin: &Origin,
        confidence: Option<f64>,
        revision: &str,
        id: &str,
    ) -> Described {
        let reference = self.references.get(id).cloned().flatten();
        let (record_ref, path) = match &reference {
            Some(reference) => (reference.clone(), format!("/{reference}")),
            None => (id.to_string(), format!("/{id}")),
        };
        let native = native_block::native_block(
            origin,
            self.person_name.as_deref().unwrap_or(UNNAMED_PERSON),
            &record_ref,
            &path,
            revision,
        );
        Described {
            confidence,
            native,
            source_type: native_block::source_type(origin, native_block::basis(origin)),
            refreshed: None,
        }
    }
}

/// An event that set a record's body, with the body it set.
pub(super) struct BodyEvent {
    pub id: String,
    pub body: String,
}

/// The confidence and `native` block of one active value.
pub(super) struct Described {
    pub confidence: Option<f64>,
    pub native: Value,
    pub source_type: &'static str,
    /// The record as it is now, when it changed after it was loaded: the
    /// description is of this record, so the caller must return this value.
    pub refreshed: Option<PrefRecord>,
}

/// The structured `evidence` object HCP stored as a JSON string facet.
fn parse_evidence(raw: Option<&String>) -> Option<Value> {
    serde_json::from_str::<Value>(raw?)
        .ok()
        .filter(Value::is_object)
}

/// A writer's authored provenance for one value.
#[derive(Clone, Debug, Default)]
pub(super) struct Provenance {
    pub confidence: Option<f64>,
    pub evidence: Option<Value>,
}

pub(super) struct Store<'a> {
    pub db: &'a Db,
    pub caller: &'a Caller,
    /// Writes this call has seen succeed.
    committed: AtomicU32,
    /// A write was issued and neither succeeded nor failed cleanly (an engine
    /// or conflict error means it was refused before any change). While this
    /// is set, whether the write landed is not known.
    in_flight: AtomicBool,
    pub person: String,
    /// OAuth client id for attribution, or `unknown`.
    pub client: String,
    pub correlation_id: String,
}

/// `update_record` arguments for a whole-body replacement, always guarded by
/// the digest of the body that was read (the digest of the empty string for
/// an empty body). A concurrent change surfaces as `Error::Conflict` through
/// `Store::guarded_update`.
fn guarded_body_set(
    id: &str,
    current_body: &str,
    new_body: &str,
    facets: Map<String, Value>,
    reason: String,
) -> Value {
    let mut args = json!({
        "id": id,
        "body_set": new_body,
        "facets": facets,
        "reason": reason,
        "sources": [],
    });
    args["if_body_digest"] = json!(sha256_hex(current_body));
    args
}

fn cell<'v>(row: &'v Value, columns: &[String], name: &str) -> Option<&'v Value> {
    match row {
        Value::Object(map) => map.get(name),
        Value::Array(cells) => columns
            .iter()
            .position(|column| column == name)
            .and_then(|index| cells.get(index)),
        _ => None,
    }
}

fn text(row: &Value, columns: &[String], name: &str) -> String {
    cell(row, columns, name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn optional_text(row: &Value, columns: &[String], name: &str) -> Option<String> {
    cell(row, columns, name)
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn number(row: &Value, columns: &[String], name: &str) -> Option<f64> {
    match cell(row, columns, name)? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Marks a future as a write to Native, so the store knows when a later error
/// leaves it unknown whether the change landed.
trait Committed<T>: std::future::Future<Output = Result<T>> + Sized {
    fn committed(self, store: &Store<'_>) -> impl std::future::Future<Output = Result<T>> {
        async move {
            store.in_flight.store(true, Ordering::SeqCst);
            let result = self.await;
            match &result {
                Ok(_) => {
                    store.committed.fetch_add(1, Ordering::SeqCst);
                    store.in_flight.store(false, Ordering::SeqCst);
                }
                // Refused before any change.
                Err(Error::Engine(_) | Error::Conflict(_)) => {
                    store.in_flight.store(false, Ordering::SeqCst);
                }
                Err(_) => {}
            }
            result
        }
    }
}

impl<T, F: std::future::Future<Output = Result<T>>> Committed<T> for F {}

impl<'a> Store<'a> {
    /// Whether the change this call was making may have landed: a write
    /// succeeded earlier in the call (so it is at least partly applied), or one
    /// ended in an error that does not say it was refused.
    pub(super) fn outcome_uncertain(&self) -> bool {
        self.committed.load(Ordering::SeqCst) > 0 || self.in_flight.load(Ordering::SeqCst)
    }

    /// A write this call issued has succeeded.
    pub(super) fn writes_committed(&self) -> bool {
        self.committed.load(Ordering::SeqCst) > 0
    }

    /// A write this call issued has neither succeeded nor been refused.
    pub(super) fn write_in_flight(&self) -> bool {
        self.in_flight.load(Ordering::SeqCst)
    }

    pub(super) fn new(db: &'a Db, caller: &'a Caller) -> Self {
        Self {
            db,
            caller,
            committed: AtomicU32::new(0),
            in_flight: AtomicBool::new(false),
            // The account identity is hashed before it is written into a facet.
            person: sha256_hex(caller.actor()),
            client: caller.oauth_client_id().unwrap_or("unknown").to_string(),
            correlation_id: uuid::Uuid::new_v4().to_string(),
        }
    }

    fn reason(&self, what: &str) -> String {
        format!(
            "HCP {what} via client {} (correlation {})",
            self.client, self.correlation_id
        )
    }

    async fn query(&self, sql: &str, parameters: Vec<Value>) -> Result<(Vec<String>, Vec<Value>)> {
        let result = Box::pin(super::super::querying::query_sql(
            self.db.clone(),
            self.caller.clone(),
            json!({ "sql": sql, "parameters": parameters }),
        ))
        .await?;
        let columns = result["columns"]
            .as_array()
            .map(|columns| {
                columns
                    .iter()
                    .filter_map(|column| column.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let rows = result["rows"].as_array().cloned().unwrap_or_default();
        Ok((columns, rows))
    }

    fn provenance_facets(&self, provenance: &Provenance) -> Result<Map<String, Value>> {
        let mut facets = Map::new();
        facets.insert(FACET_PERSON.into(), json!(self.person));
        facets.insert(FACET_CLIENT.into(), json!(self.client));
        facets.insert(FACET_CORRELATION.into(), json!(self.correlation_id));
        facets.insert(
            FACET_CONFIDENCE.into(),
            provenance.confidence.map_or(Value::Null, |c| json!(c)),
        );
        facets.insert(
            FACET_EVIDENCE.into(),
            match &provenance.evidence {
                Some(evidence) => Value::String(serde_json::to_string(evidence)?),
                None => Value::Null,
            },
        );
        Ok(facets)
    }

    // ---- catalog ---------------------------------------------------------

    pub(super) async fn load_catalog(&self) -> Result<Option<CatalogRecord>> {
        let (columns, rows) = self
            .query(
                "SELECT r.id AS id, r.body AS body FROM records r \
                 JOIN facet_values role ON role.record_id = r.id AND role.key = 'hcp.role' AND role.value = ?1 \
                 JOIN facet_values who ON who.record_id = r.id AND who.key = 'hcp.person' AND who.value = ?2 \
                 WHERE r.type = 'Document' AND r.kind = 'note' AND r.archived = 0 \
                 ORDER BY r.created_at, r.id LIMIT 1",
                vec![json!(CATALOG_ROLE), json!(self.person)],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        let body = text(row, &columns, "body");
        let catalog: Catalog = serde_json::from_str(&body)
            .map_err(|error| Error::engine(format!("HCP catalog body is unreadable: {error}")))?;
        if catalog.contract != CATALOG_CONTRACT {
            return Err(Error::engine("HCP catalog record has an unknown contract"));
        }
        Ok(Some(CatalogRecord {
            id: text(row, &columns, "id"),
            digest: sha256_hex(&body),
            catalog,
        }))
    }

    /// Persist the catalog. `existing` is the record read before the change;
    /// its body digest guards against a concurrent catalog edit.
    pub(super) async fn save_catalog(
        &self,
        existing: Option<&CatalogRecord>,
        catalog: &Catalog,
        what: &str,
    ) -> Result<String> {
        let body = serde_json::to_string_pretty(catalog)?;
        match existing {
            Some(existing) => {
                let mut facets = Map::new();
                facets.insert(FACET_CLIENT.into(), json!(self.client));
                facets.insert(FACET_CORRELATION.into(), json!(self.correlation_id));
                self.guarded_update(
                    &existing.id,
                    &existing.digest,
                    json!({
                        "id": existing.id,
                        "body_set": body,
                        "if_body_digest": existing.digest,
                        "facets": facets,
                        "reason": self.reason(what),
                        "sources": [],
                    }),
                )
                .await?;
                Ok(existing.id.clone())
            }
            None => {
                let mut facets = Map::new();
                facets.insert(FACET_ROLE.into(), json!(CATALOG_ROLE));
                facets.insert(FACET_PERSON.into(), json!(self.person));
                facets.insert(FACET_CLIENT.into(), json!(self.client));
                facets.insert(FACET_CORRELATION.into(), json!(self.correlation_id));
                let created = Box::pin(super::super::lifecycle::create_record(
                    self.db.clone(),
                    self.caller.clone(),
                    json!({
                        "type": "Document",
                        "kind": "note",
                        "name": "HCP preference catalog",
                        "body": body,
                        "facets": facets,
                        "access_policy": "account_only",
                        "reason": self.reason(what),
                        "sources": [],
                    }),
                ))
                .committed(self)
                .await;
                Self::record_id(&created?)
            }
        }
    }

    // ---- preference records ---------------------------------------------

    /// Fetch preference records for this person. `filter` is an extra `AND`
    /// clause over the aliases below (`r`, `slug`, `def`, `corr`); `params` bind
    /// from `?2`. `archived` selects archived records too (the targeted lookups
    /// that may revive one) instead of live records only.
    async fn preference_rows(
        &self,
        filter: &str,
        mut params: Vec<Value>,
        tail: &str,
        include_archived: bool,
    ) -> Result<Vec<PrefRecord>> {
        let archived_clause = if include_archived {
            ""
        } else {
            "AND r.archived = 0"
        };
        let sql = format!(
            "SELECT r.id AS id, r.body AS body, r.updated_at AS updated_at, r.archived AS archived, \
                    slug.value AS slug, def.value AS definition_id, conf.value AS confidence, \
                    client.value AS client, evidence.value AS evidence \
             FROM records r \
             JOIN facet_values slug ON slug.record_id = r.id AND slug.key = 'hcp.slug' \
             JOIN facet_values def ON def.record_id = r.id AND def.key = 'hcp.definition' \
             JOIN facet_values who ON who.record_id = r.id AND who.key = 'hcp.person' AND who.value = ?1 \
             LEFT JOIN facet_values conf ON conf.record_id = r.id AND conf.key = 'hcp.confidence' \
             LEFT JOIN facet_values client ON client.record_id = r.id AND client.key = 'hcp.client' \
             LEFT JOIN facet_values evidence ON evidence.record_id = r.id AND evidence.key = 'hcp.evidence' \
             WHERE r.type = 'Resolution' AND r.kind = 'preference' {archived_clause} {filter} \
             {tail}"
        );
        let mut all = vec![json!(self.person)];
        all.append(&mut params);
        let (columns, rows) = self.query(&sql, all).await?;
        let records: Vec<PrefRecord> = rows
            .iter()
            .map(|row| PrefRecord {
                id: text(row, &columns, "id"),
                slug: text(row, &columns, "slug"),
                definition_id: text(row, &columns, "definition_id"),
                body: text(row, &columns, "body"),
                updated_at: text(row, &columns, "updated_at"),
                archived: cell(row, &columns, "archived").and_then(Value::as_i64) == Some(1),
                confidence: number(row, &columns, "confidence"),
                client: optional_text(row, &columns, "client"),
                evidence: optional_text(row, &columns, "evidence"),
            })
            .collect();
        Ok(records)
    }

    /// Every live preference record of this person, a page at a time.
    pub(super) async fn load_preferences(&self) -> Result<Vec<PrefRecord>> {
        let page = super::limits::page_size();
        let mut all = Vec::new();
        loop {
            let batch = self
                .preference_rows(
                    "",
                    vec![],
                    &format!(
                        "ORDER BY slug.value, r.id LIMIT {page} OFFSET {}",
                        all.len()
                    ),
                    false,
                )
                .await?;
            let last = batch.len() < page;
            all.extend(batch);
            if last {
                return Ok(all);
            }
        }
    }

    /// The record for one definition, found by key rather than by scanning.
    /// An archived record is returned too (flagged) so a SET can revive it.
    pub(super) async fn find_preference(&self, definition_id: &str) -> Result<Option<PrefRecord>> {
        Ok(self
            .preference_rows(
                "AND def.value = ?2",
                vec![json!(definition_id)],
                "ORDER BY r.archived, r.created_at, r.id LIMIT 1",
                true,
            )
            .await?
            .pop())
    }

    pub(super) async fn find_preference_by_id(&self, id: &str) -> Result<Option<PrefRecord>> {
        Ok(self
            .preference_rows("AND r.id = ?2", vec![json!(id)], "LIMIT 1", false)
            .await?
            .pop())
    }

    /// Suggestions in one lifecycle state, newest target first by slug. With
    /// `live_target` the target preference record must not be archived.
    async fn suggestion_rows(
        &self,
        lifecycle: &str,
        live_target: bool,
        filter: &str,
        mut params: Vec<Value>,
        tail: &str,
    ) -> Result<Vec<SuggestionRecord>> {
        let target_live = if live_target {
            "AND t.archived = 0"
        } else {
            ""
        };
        let sql = format!(
            "SELECT a.id AS id, a.body AS body, a.updated_at AS updated_at, t.id AS target_id, \
                    slug.value AS slug, def.value AS definition_id, conf.value AS confidence, \
                    prop.value AS proposal, client.value AS client, evidence.value AS evidence \
             FROM records a \
             JOIN links l ON l.source_id = a.id AND l.relationship = 'part_of' \
             JOIN records t ON t.id = l.target_id AND t.type = 'Resolution' AND t.kind = 'preference' {target_live} \
             JOIN facet_values slug ON slug.record_id = t.id AND slug.key = 'hcp.slug' \
             JOIN facet_values def ON def.record_id = t.id AND def.key = 'hcp.definition' \
             JOIN facet_values who ON who.record_id = t.id AND who.key = 'hcp.person' AND who.value = ?1 \
             LEFT JOIN facet_values conf ON conf.record_id = a.id AND conf.key = 'hcp.confidence' \
             LEFT JOIN facet_values prop ON prop.record_id = a.id AND prop.key = 'hcp.proposal' \
             LEFT JOIN facet_values client ON client.record_id = a.id AND client.key = 'hcp.client' \
             LEFT JOIN facet_values evidence ON evidence.record_id = a.id AND evidence.key = 'hcp.evidence' \
             WHERE a.type = 'Annotation' AND a.kind = 'suggestion' AND a.lifecycle = '{lifecycle}' \
               AND a.archived = 0 {filter} {tail}"
        );
        let mut all = vec![json!(self.person)];
        all.append(&mut params);
        let (columns, rows) = self.query(&sql, all).await?;
        Ok(rows
            .iter()
            .map(|row| SuggestionRecord {
                id: text(row, &columns, "id"),
                slug: text(row, &columns, "slug"),
                definition_id: text(row, &columns, "definition_id"),
                body: text(row, &columns, "body"),
                updated_at: text(row, &columns, "updated_at"),
                confidence: number(row, &columns, "confidence"),
                hcp_authored: text(row, &columns, "proposal") == "value",
                client: optional_text(row, &columns, "client"),
                evidence: optional_text(row, &columns, "evidence"),
            })
            .collect())
    }

    /// Every open suggestion of this person, a page at a time.
    pub(super) async fn load_suggestions(&self) -> Result<Vec<SuggestionRecord>> {
        let page = super::limits::page_size();
        let mut all = Vec::new();
        loop {
            let batch = self
                .suggestion_rows(
                    "open",
                    true,
                    "",
                    vec![],
                    &format!(
                        "ORDER BY slug.value, a.id LIMIT {page} OFFSET {}",
                        all.len()
                    ),
                )
                .await?;
            let last = batch.len() < page;
            all.extend(batch);
            if last {
                return Ok(all);
            }
        }
    }

    pub(super) async fn find_suggestion_by_id(&self, id: &str) -> Result<Option<SuggestionRecord>> {
        Ok(self
            .suggestion_rows("open", true, "AND a.id = ?2", vec![json!(id)], "LIMIT 1")
            .await?
            .pop())
    }

    /// Open suggestions on one preference record, oldest first.
    pub(super) async fn open_suggestions_for_target(
        &self,
        target_id: &str,
    ) -> Result<Vec<SuggestionRecord>> {
        self.suggestion_rows(
            "open",
            true,
            "AND t.id = ?2",
            vec![json!(target_id)],
            "ORDER BY a.created_at, a.id",
        )
        .await
    }

    /// Open suggestions on one preference record whether or not the record is
    /// archived (a read only, for deciding what a SUGGEST would do before it
    /// restores anything).
    pub(super) async fn open_suggestions_for_target_any(
        &self,
        target_id: &str,
    ) -> Result<Vec<SuggestionRecord>> {
        self.suggestion_rows(
            "open",
            false,
            "AND t.id = ?2",
            vec![json!(target_id)],
            "ORDER BY a.created_at, a.id",
        )
        .await
    }

    /// Open suggestions written under one definition.
    pub(super) async fn open_suggestions_for_definition(
        &self,
        definition_id: &str,
    ) -> Result<Vec<SuggestionRecord>> {
        self.suggestion_rows(
            "open",
            true,
            "AND def.value = ?2",
            vec![json!(definition_id)],
            "ORDER BY a.created_at, a.id",
        )
        .await
    }

    /// ContextRouter suppresses a new suggestion when a REJECTED row exists
    /// for the same person and definition (`hasRejected`, at 0439d8f), whatever
    /// the rejected value was. Here "rejected" is a suggestion Native rejected.
    pub(super) async fn has_rejected_suggestion(&self, definition_id: &str) -> Result<bool> {
        Ok(!self
            .suggestion_rows(
                "rejected",
                false,
                "AND def.value = ?2",
                vec![json!(definition_id)],
                "LIMIT 1",
            )
            .await?
            .is_empty())
    }

    fn record_id(created: &Value) -> Result<String> {
        created
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::engine("create_record returned no id"))
    }

    /// Has the body of `id` moved off `sent_digest`? This is how a failed
    /// guarded write is told apart from any other failure: the engine reports
    /// a stale `if_body_digest` as an ordinary engine error (by design, see
    /// `unguarded_body_write_error`), so the only typed signal is the state.
    async fn body_moved_off(&self, id: &str, sent_digest: &str) -> Result<bool> {
        let (columns, rows) = self
            .query("SELECT body FROM records WHERE id = ?1", vec![json!(id)])
            .await?;
        Ok(match rows.first() {
            Some(row) => sha256_hex(&text(row, &columns, "body")) != sent_digest,
            None => true,
        })
    }

    /// Run a digest-guarded `update_record`. If it fails and the body has
    /// moved since `current_body` was read, report `Error::Conflict` so the
    /// caller can re-read and retry; any other failure passes through.
    async fn guarded_update(&self, id: &str, sent: &str, args: Value) -> Result<()> {
        match Box::pin(super::super::lifecycle::update_record(
            self.db.clone(),
            self.caller.clone(),
            args,
        ))
        .committed(self)
        .await
        {
            Ok(_) => Ok(()),
            Err(error @ (Error::Engine(_) | Error::Conflict(_))) => {
                if self.body_moved_off(id, sent).await.unwrap_or(false) {
                    Err(Error::conflict(format!(
                        "the body of {id} changed since it was read"
                    )))
                } else {
                    Err(error)
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Create the preference record for a definition. An empty `value_json`
    /// makes a shell (an explicitly empty body) that carries no active value
    /// yet and is its first suggestion's target. Uniqueness per person and
    /// definition rests on the caller holding the per-person lock.
    pub(super) async fn create_preference(
        &self,
        definition: &Definition,
        value_json: &str,
        provenance: &Provenance,
        what: &str,
    ) -> Result<String> {
        let mut facets = self.provenance_facets(provenance)?;
        facets.insert(FACET_SLUG.into(), json!(definition.slug));
        facets.insert(FACET_DEFINITION.into(), json!(definition.id));
        facets.insert(
            FACET_VALUE_TYPE.into(),
            json!(definition.value_type.as_str()),
        );
        facets.retain(|_, value| !value.is_null());
        let created = Box::pin(super::super::lifecycle::create_record(
            self.db.clone(),
            self.caller.clone(),
            json!({
                "type": "Resolution",
                "kind": "preference",
                "name": definition.slug,
                "body": value_json,
                "facets": facets,
                "access_policy": "account_only",
                "reason": self.reason(what),
                "sources": [],
            }),
        ))
        .committed(self)
        .await;
        Self::record_id(&created?)
    }

    /// Revise a preference in place (an empty `value_json` clears the active
    /// value and leaves a shell). History keeps the earlier value. The write
    /// is guarded by the digest of the body read, empty bodies included.
    pub(super) async fn revise_preference(
        &self,
        record: &PrefRecord,
        definition: &Definition,
        value_json: &str,
        provenance: &Provenance,
        what: &str,
    ) -> Result<()> {
        let mut facets = self.provenance_facets(provenance)?;
        facets.insert(
            FACET_VALUE_TYPE.into(),
            json!(definition.value_type.as_str()),
        );
        self.guarded_update(
            &record.id,
            &sha256_hex(&record.body),
            guarded_body_set(
                &record.id,
                &record.body,
                value_json,
                facets,
                self.reason(what),
            ),
        )
        .await
    }

    pub(super) async fn archive(&self, id: &str, archived: bool, what: &str) -> Result<()> {
        Box::pin(super::super::lifecycle::archive_record(
            self.db.clone(),
            self.caller.clone(),
            json!({ "id": id, "archived": archived, "reason": self.reason(what) }),
        ))
        .committed(self)
        .await?;
        Ok(())
    }

    // ---- suggestions -----------------------------------------------------

    /// A suggestion is always anchored to the exact body of its target, an
    /// empty body included, so it can never overwrite a value set after it.
    fn anchor(target_body: &str) -> Map<String, Value> {
        let mut facets = Map::new();
        facets.insert("proposal.precondition".into(), json!("digest"));
        facets.insert("anchor.base_digest".into(), json!(sha256_hex(target_body)));
        facets
    }

    pub(super) async fn create_suggestion(
        &self,
        target: &PrefRecord,
        value_json: &str,
        provenance: &Provenance,
        what: &str,
    ) -> Result<String> {
        let mut facets = self.provenance_facets(provenance)?;
        facets.extend(Self::anchor(&target.body));
        facets.insert(FACET_PROPOSAL.into(), json!("value"));
        facets.retain(|_, value| !value.is_null());
        let created = Box::pin(super::super::lifecycle::create_record(
            self.db.clone(),
            self.caller.clone(),
            json!({
                "type": "Annotation",
                "kind": "suggestion",
                "lifecycle": "open",
                "body": value_json,
                "links": [{ "target_id": target.id, "relationship": "part_of" }],
                "facets": facets,
                "reason": self.reason(what),
                "sources": [],
            }),
        ))
        .committed(self)
        .await?;
        Self::record_id(&created)
    }

    /// Replace an existing open suggestion's value (one SUGGESTED row per
    /// slug, as in ContextRouter), returning the replacement's id.
    ///
    /// An in-place edit cannot be guarded against Native accepting the
    /// suggestion meanwhile: acceptance changes the target and the suggestion's
    /// lifecycle but not the suggestion's body, so a body digest still matches.
    /// So the old suggestion is withdrawn first (which fails with
    /// `Error::Conflict` if it is no longer open, and which Native cannot
    /// accept once archived) and a new one is authored in its place.
    pub(super) async fn revise_suggestion(
        &self,
        suggestion: &SuggestionRecord,
        target: &PrefRecord,
        value_json: &str,
        provenance: &Provenance,
        what: &str,
    ) -> Result<String> {
        self.withdraw_suggestion(suggestion, what).await?;
        self.create_suggestion(target, value_json, provenance, what)
            .await
    }

    /// Point an HCP-authored whole-value proposal at its target's current
    /// body, for when the target's value was cleared and the proposal is still
    /// wanted. Any other suggestion keeps the precondition its author chose: a
    /// Native span edit re-anchored to a whole-body digest would replace the
    /// whole body with its snippet.
    pub(super) async fn reanchor_suggestion(
        &self,
        suggestion: &SuggestionRecord,
        target_body: &str,
        what: &str,
    ) -> Result<()> {
        if !suggestion.hcp_authored {
            return Ok(());
        }
        Box::pin(super::super::lifecycle::update_record(
            self.db.clone(),
            self.caller.clone(),
            json!({
                "id": suggestion.id,
                "facets": Self::anchor(target_body),
                "reason": self.reason(what),
                "sources": [],
            }),
        ))
        .committed(self)
        .await?;
        Ok(())
    }

    /// Withdraw an open suggestion, as ContextRouter's MCP delete removes the
    /// SUGGESTED row without recording a rejection (a rejection would suppress
    /// every later suggestion for the definition). The suggestion is archived
    /// and keeps its `open` lifecycle. If it is no longer open, or stops being
    /// open while it is withdrawn, the caller gets `Error::Conflict` and the
    /// suggestion is left as Native resolved it.
    pub(super) async fn withdraw_suggestion(&self, s: &SuggestionRecord, what: &str) -> Result<()> {
        let conflict = || Error::conflict(format!("suggestion {} is no longer open", s.id));
        if self.find_suggestion_by_id(&s.id).await?.is_none() {
            return Err(conflict());
        }
        self.archive(&s.id, true, what).await?;
        let lifecycle = self.lifecycle_of(&s.id).await?;
        if lifecycle.as_deref() != Some("open") {
            // Native resolved it between the check and the archive: undo ours.
            self.archive(&s.id, false, what).await?;
            return Err(conflict());
        }
        Ok(())
    }

    // ---- provenance of values ---------------------------------------------
    //
    // Facts come from authorised reads: `get_record` (the contribution Native
    // shows for the body-producing event), `read_attributions`, and the
    // history of the record. The one place HCP reads a provenance table
    // itself is `writer_of_event` / `writer_of_attestation`: no caller-facing
    // read exposes an action attestation's `operation`, so it is read by the
    // id of an event, or attestation, an authorised read already returned.

    /// The caller's person (as the `actors` relation names them to this
    /// caller) and the short reference of each of `ids`.
    pub(super) async fn context(&self, ids: &[String]) -> Result<Context> {
        let (columns, rows) = self
            .query(
                "SELECT person_id, display_name FROM actors WHERE actor = ?1 LIMIT 1",
                vec![json!(self.caller.actor())],
            )
            .await?;
        let borrowed: Vec<&str> = ids.iter().map(String::as_str).collect();
        let references =
            crate::mcp::record_ref::display_references_in_pool(self.db.write_pool(), &borrowed)
                .await?;
        Ok(Context {
            person_id: rows
                .first()
                .and_then(|row| optional_text(row, &columns, "person_id")),
            person_name: rows
                .first()
                .and_then(|row| optional_text(row, &columns, "display_name")),
            references,
        })
    }

    /// The valid attestation covering a content event, if any.
    async fn writer_of_event(&self, event_id: &str) -> Result<Option<Writer>> {
        self.writer_where(
            "SELECT a.id AS id, a.operation AS operation, a.channel AS channel, \
                    a.executor_kind AS executor_kind, a.principal AS principal \
               FROM provenance_action_outputs o \
               JOIN provenance_action_attestations a ON a.id = o.action_attestation_id \
              WHERE o.output_domain = 'content' AND o.output_event_id = ?1 \
             UNION ALL \
             SELECT a.id, a.operation, a.channel, a.executor_kind, a.principal \
               FROM provenance_action_events e \
               JOIN provenance_action_attestations a ON a.id = e.action_attestation_id \
              WHERE e.output_event_id = ?1 \
             LIMIT 1",
            event_id,
        )
        .await
    }

    /// An attestation by id (the one that authored an attribution).
    async fn writer_of_attestation(&self, attestation_id: &str) -> Result<Option<Writer>> {
        self.writer_where(
            "SELECT a.id AS id, a.operation AS operation, a.channel AS channel, \
                    a.executor_kind AS executor_kind, a.principal AS principal \
               FROM provenance_action_attestations a WHERE a.id = ?1",
            attestation_id,
        )
        .await
    }

    /// First row of `sql` as a `Writer`, unless the attestation was later
    /// invalidated (it then reads as unattested, as in history).
    async fn writer_where(&self, sql: &str, key: &str) -> Result<Option<Writer>> {
        let Some(row) = sqlx::query(sql)
            .bind(key)
            .fetch_optional(self.db.write_pool())
            .await?
        else {
            return Ok(None);
        };
        let id: String = row.try_get("id")?;
        let latest: Option<String> = sqlx::query_scalar(
            "SELECT status FROM provenance_attestation_validity_events \
              WHERE attestation_id = ? ORDER BY ordinal DESC LIMIT 1",
        )
        .bind(&id)
        .fetch_optional(self.db.write_pool())
        .await?;
        if latest.as_deref() == Some("invalidated") {
            return Ok(None);
        }
        let channel: Option<String> = row.try_get("channel").ok().flatten();
        // The principal stays in here: it is only compared with the caller's.
        let principal: String = row.try_get("principal")?;
        let by_owner = principal == self.caller.credential();
        let actor_name = if by_owner {
            None
        } else {
            // Someone else acted. Name them only through the relation that
            // lists the actors Native discloses to this caller.
            let (columns, rows) = self
                .query(
                    "SELECT display_name FROM actors WHERE actor = ?1 LIMIT 1",
                    vec![json!(principal)],
                )
                .await?;
            rows.first()
                .and_then(|row| optional_text(row, &columns, "display_name"))
        };
        Ok(Some(Writer {
            operation: row.try_get("operation")?,
            channel: Channel::from_stored(channel.as_deref()),
            executor_kind: row.try_get("executor_kind")?,
            attestation_id: id,
            by_owner,
            actor_name,
        }))
    }

    /// Attribution annotations that speak about exactly this revision of the
    /// value, about this person, still standing.
    async fn attributions_for(
        &self,
        record: &PrefRecord,
        context: &Context,
        body_event_id: &str,
    ) -> Result<Vec<Attribution>> {
        let Some(person_id) = context.person_id.as_deref() else {
            return Ok(Vec::new());
        };
        let read = Box::pin(super::super::attribution::read_attributions(
            self.db.clone(),
            self.caller.clone(),
            json!({ "bearer_id": record.id, "limit": ATTRIBUTION_WINDOW }),
        ))
        .await;
        let result = match read {
            Ok(result) => result,
            // Not readable by this caller: no fact, so no attribution.
            Err(Error::Engine(_)) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let digest = sha256_hex(&record.body);
        let mut found = Vec::new();
        for claim in result["attributions"].as_array().into_iter().flatten() {
            let target = &claim["target"];
            let assertion = &claim["assertion"];
            let about_this_revision = target["scope"] == "whole_revision"
                && target["source_event_id"] == body_event_id
                && target["source_body_sha256"] == digest.as_str();
            let about_the_person = assertion["attributed_subject"]["kind"] == "person_record"
                && assertion["attributed_subject"]["ref"] == person_id;
            let relation = assertion["relation"].as_str().unwrap_or_default();
            let standing = claim["retraction"].is_null()
                && claim["successor_ids"]
                    .as_array()
                    .is_none_or(|successors| successors.is_empty());
            if !(about_this_revision
                && about_the_person
                && standing
                && matches!(relation, "expresses_view" | "endorses"))
            {
                continue;
            }
            // Only the owner's own claims count: a collaborator's attribution
            // speaks for the collaborator, whatever it says about the owner.
            let author = match assertion["action_attestation_id"].as_str() {
                Some(id) => self.writer_of_attestation(id).await?,
                None => None,
            };
            let Some(author) = author.filter(|author| author.by_owner) else {
                continue;
            };
            let via = if assertion["claim_mode"] == "declaration" || author.is_person_channel() {
                // A direct declaration Native verified at trusted ingress, or
                // made through a person channel.
                Via::Person
            } else if author.channel == Channel::Mcp {
                Via::Agent
            } else {
                Via::Unknown
            };
            found.push(Attribution {
                affirms: assertion["polarity"] == "affirmed",
                via,
                rationale: assertion["rationale"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            });
        }
        Ok(found)
    }

    /// Where the current value of `record` came from, or `None` when the
    /// event that last set the body did not produce the body `record` holds
    /// (the body moved between loading it and looking here), so provenance
    /// is never reported for a different value.
    async fn origin_of(&self, record: &PrefRecord, context: &Context) -> Result<Option<Origin>> {
        let mut origin = Origin::default();
        let Some(body_event) = self.latest_body_event(&record.id).await? else {
            return Ok(Some(origin));
        };
        if body_event.body != record.body {
            return Ok(None);
        }
        origin.writer = self.writer_of_event(&body_event.id).await?;
        match &origin.writer {
            Some(writer) if writer.is_hcp() => {
                origin.client = record.client.clone();
                origin.evidence = parse_evidence(record.evidence.as_ref());
            }
            Some(writer) => {
                origin.accepted = self.accepted_producer(&body_event, writer).await?;
            }
            None => {}
        }
        origin.attributions = self
            .attributions_for(record, context, &body_event.id)
            .await?;
        Ok(Some(origin))
    }

    /// What accepting suggestions did to produce the body, when a
    /// `resolve_suggestions` action did.
    ///
    /// Only the **immutable record of that action** is used: the content events
    /// its attestation lists as outputs. The live suggestion records are not,
    /// because a suggestion can be edited, archived or deleted afterwards. The
    /// action must have resolved exactly one suggestion (one `accepted`
    /// lifecycle event) and written the body being described. Anything else
    /// (several suggestions, outputs that do not show it, a suggestion Native
    /// will no longer show) is `ambiguous`, which derives nothing.
    async fn accepted_producer(
        &self,
        body_event: &BodyEvent,
        body_writer: &Writer,
    ) -> Result<Option<Accepted>> {
        if !body_writer.operation.starts_with("resolve_suggestions") {
            return Ok(None);
        }
        let outputs = sqlx::query(
            "SELECT e.id AS id, e.seq AS seq, e.record_id AS record_id, e.type AS type, \
                    e.payload AS payload \
               FROM provenance_action_outputs o \
               JOIN content_events e ON e.id = o.output_event_id \
              WHERE o.action_attestation_id = ?1 AND o.output_domain = 'content'",
        )
        .bind(&body_writer.attestation_id)
        .fetch_all(self.db.write_pool())
        .await?;
        let mut wrote_the_body = false;
        let mut resolved: Vec<(String, i64)> = Vec::new();
        for output in &outputs {
            let id: String = output.try_get("id")?;
            let payload: Option<String> = output.try_get("payload")?;
            let accepted = output.try_get::<String, _>("type")? == "record.updated"
                && payload
                    .as_deref()
                    .and_then(|payload| serde_json::from_str::<Value>(payload).ok())
                    .is_some_and(|payload| payload["lifecycle"] == "accepted");
            if accepted {
                resolved.push((output.try_get("record_id")?, output.try_get("seq")?));
            }
            wrote_the_body |= id == body_event.id;
        }
        let [(suggestion_id, accepted_seq)] = resolved.as_slice() else {
            return Ok(Some(Accepted::ambiguous()));
        };
        if !wrote_the_body {
            return Ok(Some(Accepted::ambiguous()));
        }
        // Whether HCP authored the proposal, as of the acceptance: only that
        // decides whether its confidence and evidence (which describe the
        // proposal) are HCP's. It is not the basis and not who recorded the body.
        let author = match self
            .latest_body_event_before(suggestion_id, *accepted_seq)
            .await
        {
            Ok(Some(event)) => self.writer_of_event(&event.id).await?,
            Ok(None) | Err(Error::Engine(_)) => None,
            Err(error) => return Err(error),
        };
        let hcp_authored = author.as_ref().is_some_and(Writer::is_hcp);
        let (columns, facets) = self
            .query(
                "SELECT key, value FROM facet_values \
                  WHERE record_id = ?1 AND key IN ('hcp.confidence', 'hcp.evidence')",
                vec![json!(suggestion_id)],
            )
            .await?;
        let facet = |key: &str| {
            facets
                .iter()
                .find(|row| text(row, &columns, "key") == key)
                .map(|row| text(row, &columns, "value"))
        };
        Ok(Some(Accepted {
            ambiguous: false,
            confidence: facet("hcp.confidence")
                .and_then(|confidence| confidence.parse().ok())
                .filter(|_| hcp_authored),
            evidence: if hcp_authored {
                parse_evidence(facet("hcp.evidence").as_ref())
            } else {
                None
            },
        }))
    }

    /// The `native` block of a definition, which lives in the catalog record.
    pub(super) async fn describe_definition(
        &self,
        catalog_id: &str,
        definition: &Definition,
        revision: &str,
    ) -> Result<Value> {
        let context = self.context(&[catalog_id.to_string()]).await?;
        let reference = context.references.get(catalog_id).cloned().flatten();
        let (record_ref, path) = match &reference {
            Some(reference) => (reference.clone(), format!("/{reference}")),
            None => (catalog_id.to_string(), format!("/{catalog_id}")),
        };
        Ok(native_block::definition_block(
            definition.client.as_deref(),
            &record_ref,
            &path,
            revision,
        ))
    }

    /// Confidence and the `native` block for each active value, in order.
    pub(super) async fn describe_active(&self, records: &[PrefRecord]) -> Result<Vec<Described>> {
        let ids: Vec<String> = records.iter().map(|record| record.id.clone()).collect();
        let context = self.context(&ids).await?;
        let mut described = Vec::with_capacity(records.len());
        for record in records {
            let mut current = record.clone();
            let mut refreshed = false;
            let mut origin = None;
            // The body can move between loading it and looking up where it came
            // from. Look again at the record as it is now; if its producer still
            // does not match its body, claim no asserter rather than describe a
            // different value.
            for attempt in 0..2 {
                origin = if current.has_value() {
                    self.origin_of(&current, &context).await?
                } else {
                    Some(Origin::default())
                };
                if origin.is_some() || attempt == 1 {
                    break;
                }
                if let Some(fresh) = self.find_preference_by_id(&current.id).await? {
                    refreshed = fresh.body != current.body;
                    current = fresh;
                }
            }
            let origin = origin.unwrap_or_default();
            let mut item = context.describe(
                &origin,
                origin.confidence(current.confidence),
                &sha256_hex(&current.body),
                &current.id,
            );
            if refreshed {
                item.refreshed = Some(current);
            }
            described.push(item);
        }
        Ok(described)
    }

    /// The `native` block for each open suggestion, in order. A suggestion's
    /// confidence is its own `hcp.confidence`, already on the record.
    pub(super) async fn describe_suggestions(
        &self,
        suggestions: &[&SuggestionRecord],
    ) -> Result<Vec<Described>> {
        let ids: Vec<String> = suggestions
            .iter()
            .map(|suggestion| suggestion.id.clone())
            .collect();
        let context = self.context(&ids).await?;
        let mut blocks = Vec::with_capacity(suggestions.len());
        for suggestion in suggestions {
            let mut origin = Origin::default();
            // Only a producer whose body is the suggestion's body describes it.
            if let Some(event) = self.latest_body_event(&suggestion.id).await? {
                if event.body == suggestion.body {
                    origin.writer = self.writer_of_event(&event.id).await?;
                    if origin.writer.as_ref().is_some_and(Writer::is_hcp) {
                        origin.client = suggestion.client.clone();
                        origin.evidence = parse_evidence(suggestion.evidence.as_ref());
                    }
                }
            }
            blocks.push(context.describe(
                &origin,
                suggestion.confidence,
                &sha256_hex(&suggestion.body),
                &suggestion.id,
            ));
        }
        Ok(blocks)
    }

    /// Newest history event of `id` satisfying `pick`, paging newest first.
    async fn newest_event<T>(
        &self,
        id: &str,
        pick: impl Fn(&Value) -> Option<T>,
    ) -> Result<Option<T>> {
        let mut cursor: Option<i64> = None;
        loop {
            let mut args = json!({
                "record_id": id, "order": "newest_first", "limit": 100, "detail": "full"
            });
            if let Some(cursor) = cursor {
                args["after_local_seq"] = json!(cursor);
            }
            let page = Box::pin(super::super::history::get_history(
                self.db.clone(),
                self.caller.clone(),
                args,
            ))
            .await?;
            for event in page["events"].as_array().into_iter().flatten() {
                if let Some(found) = pick(event) {
                    return Ok(Some(found));
                }
            }
            match page["next_after_local_seq"].as_i64() {
                Some(next) => cursor = Some(next),
                None => return Ok(None),
            }
        }
    }

    /// The newest event that set the record's body.
    async fn latest_body_event(&self, id: &str) -> Result<Option<BodyEvent>> {
        self.latest_body_event_before(id, i64::MAX).await
    }

    /// The newest body-setting event with a sequence below `before_seq`.
    async fn latest_body_event_before(
        &self,
        id: &str,
        before_seq: i64,
    ) -> Result<Option<BodyEvent>> {
        self.newest_event(id, |event| {
            let seq = event["local_seq"].as_i64()?;
            let sets_body = matches!(
                event["type"].as_str(),
                Some("record.created" | "record.updated")
            ) && event["payload"].get("body").is_some();
            if !sets_body || seq >= before_seq {
                return None;
            }
            Some(BodyEvent {
                id: event["id"].as_str()?.to_string(),
                body: event["payload"]["body"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
            })
        })
        .await
    }

    async fn lifecycle_of(&self, id: &str) -> Result<Option<String>> {
        let (columns, rows) = self
            .query(
                "SELECT lifecycle FROM records WHERE id = ?1",
                vec![json!(id)],
            )
            .await?;
        Ok(rows
            .first()
            .map(|row| text(row, &columns, "lifecycle"))
            .filter(|lifecycle| !lifecycle.is_empty()))
    }
}
