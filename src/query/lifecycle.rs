//! Governed interpretation of the shared lifecycle carrier.
//!
//! A lifecycle token is meaningful only in the effective schema context of
//! its record. This module keeps that schema and vocabulary resolution in the
//! read layer so generic consumers do not grow their own token lists.

use std::collections::HashMap;

use serde::Serialize;

use crate::authorization::Principal;
use crate::db::Db;
use crate::error::{Error, Result};
use crate::portable_sql::{
    BorrowedSqliteStatementExecutor, ColumnSpec, DomainStatementExecutor, LogicalType,
    NormalizedRow, NormalizedValue, StatementKind, StatementTemplate,
};

use super::cascade::{self, SchemaConfigRow};

pub const REASON_NO_GOVERNING_VOCABULARY: &str = "no_governing_vocabulary";
pub const REASON_UNKNOWN_OR_INACTIVE_VALUE: &str = "unknown_or_inactive_value";
pub const REASON_UNINTERPRETABLE_SCHEMA: &str = "uninterpretable_schema_or_value";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleAxis {
    pub key: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LifecycleVocabularyIdentity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernedLifecycleValue {
    pub raw: String,
    /// The active canonical value identity, including when `raw` is an alias.
    pub id: String,
    pub canonical: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GovernedLifecycleInterpretation {
    pub axis: LifecycleAxis,
    pub vocabulary: LifecycleVocabularyIdentity,
    pub value: GovernedLifecycleValue,
    pub terminality: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AbsentLifecycleInterpretation {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub axis: Option<LifecycleAxis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vocabulary: Option<LifecycleVocabularyIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UnclassifiedLifecycleInterpretation {
    pub raw: String,
    pub reason: &'static str,
}

/// The sole structured-read projection of the physical lifecycle carrier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LifecycleInterpretation {
    Governed(GovernedLifecycleInterpretation),
    Absent(AbsentLifecycleInterpretation),
    Unclassified(UnclassifiedLifecycleInterpretation),
}

#[derive(Debug, Clone)]
struct VocabularyValueState {
    id: String,
    vocabulary_id: String,
    value: String,
    status: String,
    terminality: String,
    alias_of: Option<String>,
}

#[derive(Debug, Default)]
struct VocabularyIndex {
    /// Both vocabulary ids and names address the same vocabulary identity.
    refs: HashMap<String, String>,
    names_by_id: HashMap<String, String>,
    values_by_id: HashMap<String, VocabularyValueState>,
    values_by_vocab_and_value: HashMap<(String, String), String>,
}

fn text(row: &NormalizedRow, column: &str) -> Result<String> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(value.clone()),
        _ => Err(Error::engine(format!(
            "lifecycle interpretation column '{column}' is invalid"
        ))),
    }
}

fn optional_text(row: &NormalizedRow, column: &str) -> Result<Option<String>> {
    match row.get(column) {
        Some(NormalizedValue::Text(value)) => Ok(Some(value.clone())),
        Some(NormalizedValue::Null) => Ok(None),
        _ => Err(Error::engine(format!(
            "lifecycle interpretation column '{column}' is invalid"
        ))),
    }
}

fn select(relation: &'static str, fragments: &'static [&'static str]) -> Result<StatementTemplate> {
    StatementTemplate::new(StatementKind::Select, relation, fragments).map_err(|error| {
        Error::engine(format!(
            "read lifecycle interpretation: {}",
            error.stable_message()
        ))
    })
}

impl VocabularyIndex {
    async fn load_with<E: DomainStatementExecutor>(executor: &mut E) -> Result<Self> {
        let vocabularies = select(
            "vocabularies",
            &["SELECT id, name FROM {{relation}} ORDER BY id"],
        )?;
        let vocabulary_rows = executor
            .fetch_all(
                &vocabularies,
                &[],
                &[
                    ColumnSpec::required("id", LogicalType::Text),
                    ColumnSpec::required("name", LogicalType::Text),
                ],
            )
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "read lifecycle vocabularies: {}",
                    error.stable_message()
                ))
            })?;
        let values = select(
            "vocabulary_values",
            &["SELECT id, vocabulary_id, value, status, terminality, alias_of FROM {{relation}} ORDER BY id"],
        )?;
        let value_rows = executor
            .fetch_all(
                &values,
                &[],
                &[
                    ColumnSpec::required("id", LogicalType::Text),
                    ColumnSpec::required("vocabulary_id", LogicalType::Text),
                    ColumnSpec::required("value", LogicalType::Text),
                    ColumnSpec::required("status", LogicalType::Text),
                    ColumnSpec::required("terminality", LogicalType::Text),
                    ColumnSpec::nullable("alias_of", LogicalType::Text),
                ],
            )
            .await
            .map_err(|error| {
                Error::engine(format!(
                    "read lifecycle vocabulary values: {}",
                    error.stable_message()
                ))
            })?;

        let mut index = Self::default();
        for row in vocabulary_rows {
            let id = text(&row, "id")?;
            let name = text(&row, "name")?;
            index.refs.insert(id.clone(), id.clone());
            index.refs.insert(name.clone(), id.clone());
            index.names_by_id.insert(id, name);
        }
        for row in value_rows {
            let state = VocabularyValueState {
                id: text(&row, "id")?,
                vocabulary_id: text(&row, "vocabulary_id")?,
                value: text(&row, "value")?,
                status: text(&row, "status")?,
                terminality: text(&row, "terminality")?,
                alias_of: optional_text(&row, "alias_of")?,
            };
            index.values_by_vocab_and_value.insert(
                (state.vocabulary_id.clone(), state.value.clone()),
                state.id.clone(),
            );
            index.values_by_id.insert(state.id.clone(), state);
        }
        Ok(index)
    }

    fn identity(&self, vocabulary_id: &str) -> Option<LifecycleVocabularyIdentity> {
        Some(LifecycleVocabularyIdentity {
            id: vocabulary_id.to_string(),
            name: self.names_by_id.get(vocabulary_id)?.clone(),
        })
    }

    fn canonical_value(&self, vocabulary_id: &str, raw: &str) -> Option<&VocabularyValueState> {
        let value_id = self
            .values_by_vocab_and_value
            .get(&(vocabulary_id.to_string(), raw.to_string()))?;
        let value = self.values_by_id.get(value_id)?;
        let canonical = match value.alias_of.as_deref() {
            Some(alias_of) => {
                if value.status != "deprecated" {
                    return None;
                }
                let canonical = self.values_by_id.get(alias_of)?;
                if canonical.vocabulary_id != value.vocabulary_id
                    || canonical.alias_of.is_some()
                    || canonical.status != "active"
                {
                    return None;
                }
                canonical
            }
            None if value.status == "active" => value,
            None => return None,
        };
        Some(canonical)
    }
}

/// A read-only, point-in-time interpreter that amortizes schema and vocabulary
/// reads across a bounded structured read.
pub struct LifecycleInterpreter {
    schema_rows: Vec<SchemaConfigRow>,
    vocabularies: VocabularyIndex,
}

impl LifecycleInterpreter {
    pub async fn load(db: &Db, principal: Option<Principal<'_>>) -> Result<Self> {
        let schema_rows = cascade::schema_config_rows_for_principal(db, principal).await?;
        Self::load_from_pool(db.write_pool(), schema_rows).await
    }

    /// Load against a pool after the caller has selected its visible schema
    /// rows. This is the ordinary live/read-lens construction seam.
    pub async fn load_from_pool(
        pool: &sqlx::SqlitePool,
        schema_rows: Vec<SchemaConfigRow>,
    ) -> Result<Self> {
        let mut connection = pool.acquire().await?;
        Self::load_from_connection(&mut connection, schema_rows).await
    }

    /// Load without escaping a caller-owned SQLite snapshot/transaction.
    pub async fn load_from_connection(
        connection: &mut sqlx::SqliteConnection,
        schema_rows: Vec<SchemaConfigRow>,
    ) -> Result<Self> {
        let mut executor = BorrowedSqliteStatementExecutor::new(connection);
        Self::load_from_rows_with(&mut executor, schema_rows).await
    }

    /// Portable construction with the same caller-relative anchored-schema
    /// visibility used by the SQLite read lens.
    #[cfg(any(feature = "postgres", feature = "turso-local"))]
    pub(crate) async fn load_visible_with<E: DomainStatementExecutor>(
        executor: &mut E,
        principal: Principal<'_>,
    ) -> Result<Self> {
        let rows = cascade::schema_config_rows_with(executor).await?;
        let mut bearer_visibility = HashMap::new();
        let mut visible = Vec::with_capacity(rows.len());
        for row in rows {
            let allowed = match row.applies_to_collection_id.as_deref() {
                None => true,
                Some(record_id) => match bearer_visibility.get(record_id) {
                    Some(allowed) => *allowed,
                    None => {
                        let allowed = crate::authorization::allows_record_with(
                            executor,
                            principal,
                            record_id,
                            crate::authorization::Capability::View,
                        )
                        .await?;
                        bearer_visibility.insert(record_id.to_string(), allowed);
                        allowed
                    }
                },
            };
            if allowed {
                visible.push(row);
            }
        }
        Self::load_from_rows_with(executor, visible).await
    }

    pub(crate) async fn load_from_rows_with<E: DomainStatementExecutor>(
        executor: &mut E,
        schema_rows: Vec<SchemaConfigRow>,
    ) -> Result<Self> {
        Ok(Self {
            schema_rows,
            vocabularies: VocabularyIndex::load_with(executor).await?,
        })
    }

    fn context(
        &self,
        record_type: &str,
        kind: Option<&str>,
        bearer_id: Option<&str>,
    ) -> (Option<LifecycleAxis>, Option<LifecycleVocabularyIdentity>) {
        let facets =
            cascade::facets_for_record_context(&self.schema_rows, record_type, kind, bearer_id);
        let Some(shape) = facets.get("lifecycle") else {
            return (None, None);
        };
        let axis = shape.get("axis").and_then(|axis| {
            let axis = axis.as_object()?;
            if axis.len() != 2 {
                return None;
            }
            let key = axis.get("key")?.as_str()?;
            let label = axis.get("label")?.as_str()?;
            if key.trim().is_empty() || label.trim().is_empty() {
                return None;
            }
            Some(LifecycleAxis {
                key: key.to_string(),
                label: label.to_string(),
            })
        });
        let vocabulary = shape
            .get("vocab")
            .or_else(|| shape.get("vocab_ref"))
            .and_then(serde_json::Value::as_str)
            .map(crate::meta::vocabulary::resolve_vocab_ref)
            .and_then(|reference| self.vocabularies.refs.get(reference))
            .and_then(|id| self.vocabularies.identity(id));
        (axis, vocabulary)
    }

    /// Interpret one nullable stored lifecycle through the effective record
    /// shape and one-hop active-canonical vocabulary semantics.
    pub fn interpret(
        &self,
        record_type: &str,
        kind: Option<&str>,
        bearer_id: Option<&str>,
        lifecycle: Option<&str>,
    ) -> LifecycleInterpretation {
        let (axis, vocabulary) = self.context(record_type, kind, bearer_id);
        let facets =
            cascade::facets_for_record_context(&self.schema_rows, record_type, kind, bearer_id);
        let has_vocabulary_declaration = facets
            .get("lifecycle")
            .and_then(|shape| shape.get("vocab").or_else(|| shape.get("vocab_ref")))
            .is_some();
        let Some(raw) = lifecycle else {
            return LifecycleInterpretation::Absent(AbsentLifecycleInterpretation {
                axis,
                vocabulary,
            });
        };
        let Some(axis) = axis else {
            let reason = if has_vocabulary_declaration {
                REASON_UNINTERPRETABLE_SCHEMA
            } else {
                REASON_NO_GOVERNING_VOCABULARY
            };
            return LifecycleInterpretation::Unclassified(UnclassifiedLifecycleInterpretation {
                raw: raw.to_string(),
                reason,
            });
        };
        let Some(vocabulary) = vocabulary else {
            let reason = if has_vocabulary_declaration {
                REASON_UNINTERPRETABLE_SCHEMA
            } else {
                REASON_NO_GOVERNING_VOCABULARY
            };
            return LifecycleInterpretation::Unclassified(UnclassifiedLifecycleInterpretation {
                raw: raw.to_string(),
                reason,
            });
        };
        let Some(canonical) = self.vocabularies.canonical_value(&vocabulary.id, raw) else {
            return LifecycleInterpretation::Unclassified(UnclassifiedLifecycleInterpretation {
                raw: raw.to_string(),
                reason: REASON_UNKNOWN_OR_INACTIVE_VALUE,
            });
        };
        if !matches!(
            canonical.terminality.as_str(),
            "open" | "terminal_positive" | "terminal_negative"
        ) {
            return LifecycleInterpretation::Unclassified(UnclassifiedLifecycleInterpretation {
                raw: raw.to_string(),
                reason: REASON_UNINTERPRETABLE_SCHEMA,
            });
        }
        LifecycleInterpretation::Governed(GovernedLifecycleInterpretation {
            axis,
            vocabulary,
            value: GovernedLifecycleValue {
                raw: raw.to_string(),
                id: canonical.id.clone(),
                canonical: canonical.value.clone(),
            },
            terminality: canonical.terminality.clone(),
        })
    }

    /// Match scalar lifecycle filter tokens within this candidate record's
    /// effective vocabulary. Aliases canonicalize only inside that vocabulary;
    /// unclassified raw values retain the legacy exact-token fallback.
    pub fn matches_filter(
        &self,
        record_type: &str,
        kind: Option<&str>,
        bearer_id: Option<&str>,
        lifecycle: Option<&str>,
        requested: &[String],
    ) -> bool {
        if requested.is_empty() {
            return true;
        }
        match self.interpret(record_type, kind, bearer_id, lifecycle) {
            LifecycleInterpretation::Governed(governed) => requested.iter().any(|token| {
                self.vocabularies
                    .canonical_value(&governed.vocabulary.id, token)
                    .is_some_and(|value| value.id == governed.value.id)
            }),
            LifecycleInterpretation::Unclassified(unclassified) => {
                requested.iter().any(|token| token == &unclassified.raw)
            }
            LifecycleInterpretation::Absent(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn interpreter() -> LifecycleInterpreter {
        let schema_rows = vec![SchemaConfigRow {
            id: "pack:test".into(),
            layer: "pack".into(),
            name: None,
            data: json!({
                "shapes": {
                    "WorkItem:task": {
                        "facets": {
                            "lifecycle": {
                                "axis": { "key": "work_status", "label": "Work status" },
                                "vocab_ref": "task-state",
                                "required": true
                            }
                        }
                    }
                }
            }),
            applies_to_collection_id: None,
            version_lineage: None,
            created_at: String::new(),
        }];
        let canonical = VocabularyValueState {
            id: "vv:voc:task-state:completed".into(),
            vocabulary_id: "voc:task-state".into(),
            value: "completed".into(),
            status: "active".into(),
            terminality: "terminal_positive".into(),
            alias_of: None,
        };
        let alias = VocabularyValueState {
            id: "vv:voc:task-state:done".into(),
            vocabulary_id: "voc:task-state".into(),
            value: "done".into(),
            status: "deprecated".into(),
            terminality: "terminal_positive".into(),
            alias_of: Some(canonical.id.clone()),
        };
        let mut vocabularies = VocabularyIndex::default();
        vocabularies
            .refs
            .insert("task-state".into(), "voc:task-state".into());
        vocabularies
            .refs
            .insert("voc:task-state".into(), "voc:task-state".into());
        vocabularies
            .names_by_id
            .insert("voc:task-state".into(), "task-state".into());
        for value in [canonical, alias] {
            vocabularies.values_by_vocab_and_value.insert(
                (value.vocabulary_id.clone(), value.value.clone()),
                value.id.clone(),
            );
            vocabularies.values_by_id.insert(value.id.clone(), value);
        }
        LifecycleInterpreter {
            schema_rows,
            vocabularies,
        }
    }

    #[test]
    fn governed_alias_serializes_raw_and_canonical_identity() {
        let interpreter = interpreter();
        let value = interpreter.interpret("WorkItem", Some("task"), None, Some("done"));
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            json!({
                "status": "governed",
                "axis": { "key": "work_status", "label": "Work status" },
                "vocabulary": { "id": "voc:task-state", "name": "task-state" },
                "value": {
                    "raw": "done",
                    "id": "vv:voc:task-state:completed",
                    "canonical": "completed"
                },
                "terminality": "terminal_positive"
            })
        );
        assert!(interpreter.matches_filter(
            "WorkItem",
            Some("task"),
            None,
            Some("completed"),
            &["done".into()]
        ));
    }

    #[test]
    fn absence_retains_governance_and_failure_retains_raw_reason() {
        let interpreter = interpreter();
        assert_eq!(
            serde_json::to_value(interpreter.interpret("WorkItem", Some("task"), None, None))
                .unwrap(),
            json!({
                "status": "absent",
                "axis": { "key": "work_status", "label": "Work status" },
                "vocabulary": { "id": "voc:task-state", "name": "task-state" }
            })
        );
        assert_eq!(
            serde_json::to_value(interpreter.interpret(
                "WorkItem",
                Some("task"),
                None,
                Some("invented")
            ))
            .unwrap(),
            json!({
                "status": "unclassified",
                "raw": "invented",
                "reason": "unknown_or_inactive_value"
            })
        );
    }

    #[test]
    fn unclassified_reasons_and_ungoverned_absence_remain_distinct() {
        let mut interpreter = interpreter();
        assert_eq!(
            serde_json::to_value(interpreter.interpret(
                "Document",
                Some("note"),
                None,
                Some("bespoke")
            ))
            .unwrap(),
            json!({
                "status": "unclassified",
                "raw": "bespoke",
                "reason": "no_governing_vocabulary"
            })
        );
        assert_eq!(
            serde_json::to_value(interpreter.interpret("Resolution", Some("decision"), None, None))
                .unwrap(),
            json!({ "status": "absent" })
        );

        interpreter.schema_rows[0].data["shapes"]["WorkItem:task"]["facets"]["lifecycle"]["axis"] =
            json!({ "key": "work_status" });
        assert_eq!(
            serde_json::to_value(interpreter.interpret(
                "WorkItem",
                Some("task"),
                None,
                Some("completed")
            ))
            .unwrap(),
            json!({
                "status": "unclassified",
                "raw": "completed",
                "reason": "uninterpretable_schema_or_value"
            })
        );
    }
}
