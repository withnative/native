use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

pub const CHANGE_SUMMARY_RESULT_SCHEMA: &str = "native.change-summary.v1";
pub const CHANGE_SUMMARY_SELECTION_SCHEMA: &str = "native.change-summary.selection.v1";
pub const CHANGE_SUMMARY_SCOPE_SCHEMA: &str = "native.change-summary.scope.v1";
pub const CHANGE_SUMMARY_RESULT_CONTRACT_ID: &str = "native.change-summary";
pub const CHANGE_SUMMARY_RESULT_CONTRACT_VERSION: u32 = 1;
pub const CHANGE_SUMMARY_QUERY_CONTRACT_ID: &str = "native.change-summary.query";
pub const CHANGE_SUMMARY_QUERY_CONTRACT_VERSION: u32 = 1;
pub const CHANGE_SUMMARY_OUTPUT_CONTRACT_ID: &str = "native.change-summary.markdown";
pub const CHANGE_SUMMARY_OUTPUT_CONTRACT_VERSION: u32 = 1;
pub const MAX_CHANGE_SUMMARY_CONTEXT_RECORDS: usize = 16;
pub const MAX_CHANGE_SUMMARY_INPUTS: usize = 19;
pub const MAX_EFFECTIVE_WORK_INTERVAL_SECONDS: i64 = 366 * 24 * 60 * 60;

pub const CHANGE_SUMMARY_RESULT_SCHEMA_JSON: &str = r##"{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"native.change-summary.v1",
  "type":"object",
  "additionalProperties":false,
  "required":["schema","effective_work_interval","renderer","source_groups","title","overview","items"],
  "properties":{
    "schema":{"const":"native.change-summary.v1"},
    "effective_work_interval":{"$ref":"#/$defs/effectiveWorkInterval"},
    "renderer":{"$ref":"#/$defs/renderer"},
    "source_groups":{
      "type":"array","minItems":3,"maxItems":3,
      "items":{"$ref":"#/$defs/sourceGroup"}
    },
    "title":{"type":"string","minLength":1,"maxLength":160},
    "overview":{"type":"string","minLength":1,"maxLength":4000},
    "items":{
      "type":"array","minItems":1,"maxItems":1,
      "items":{
        "type":"object","additionalProperties":false,
        "required":["heading","summary","citations","materiality","link_suggestions"],
        "properties":{
          "heading":{"type":"string","minLength":1,"maxLength":200},
          "summary":{"type":"string","minLength":1,"maxLength":8000},
          "citations":{
            "type":"array","minItems":3,"maxItems":19,
            "items":{"$ref":"#/$defs/citation"}
          },
          "materiality":{
            "type":"object","additionalProperties":false,
            "required":["summary","references"],
            "properties":{
              "summary":{"type":"string","minLength":1,"maxLength":2000},
              "references":{
                "type":"array","maxItems":16,
                "items":{
                  "type":"object","additionalProperties":false,
                  "required":["record_id","rationale"],
                  "properties":{
                    "record_id":{"type":"string","minLength":1,"maxLength":256},
                    "rationale":{"type":"string","minLength":1,"maxLength":1000}
                  }
                }
              }
            }
          },
          "link_suggestions":{
            "type":"object","additionalProperties":false,
            "required":["work_items","outcomes"],
            "properties":{
              "work_items":{"type":"array","maxItems":16,"items":{"$ref":"#/$defs/workItemSuggestion"}},
              "outcomes":{"type":"array","maxItems":16,"items":{"$ref":"#/$defs/outcomeSuggestion"}}
            }
          }
        }
      }
    }
  },
  "$defs":{
    "effectiveWorkInterval":{
      "type":"object","additionalProperties":false,
      "required":["started_at","ended_at"],
      "properties":{
        "started_at":{"type":"string","format":"date-time","minLength":24,"maxLength":24},
        "ended_at":{"type":"string","format":"date-time","minLength":24,"maxLength":24}
      }
    },
    "renderer":{
      "type":"object","additionalProperties":false,
      "required":["id","revision","spec_sha256"],
      "properties":{
        "id":{"const":"native.change-summary.markdown.renderer"},
        "revision":{"const":"1"},
        "spec_sha256":{"const":"110924767e9186810bb4bc9a08a8807ce78dfc6f7e7e24ffe9d8f075284b2c0d"}
      }
    },
    "citation":{
      "type":"object","additionalProperties":false,
      "required":["ordinal","input_role","input_kind","portable_id","sha256"],
      "properties":{
        "ordinal":{"type":"integer","minimum":0,"maximum":18},
        "input_role":{"enum":["context","source"]},
        "input_kind":{"enum":["content_event","record_body"]},
        "portable_id":{"type":"string","minLength":1,"maxLength":256},
        "sha256":{"type":"string","pattern":"^[0-9a-f]{64}$"}
      }
    },
    "sourceGroup":{
      "type":"object","additionalProperties":false,
      "required":["run_key","source_ordinal"],
      "properties":{
        "run_key":{"type":"string","minLength":1,"maxLength":512},
        "source_ordinal":{"type":"integer","minimum":0,"maximum":18}
      }
    },
    "workItemSuggestion":{
      "type":"object","additionalProperties":false,
      "required":["record_id","relationship","rationale"],
      "properties":{
        "record_id":{"type":"string","minLength":1,"maxLength":256},
        "relationship":{"enum":["derived_from","implements","relates_to"]},
        "rationale":{"type":"string","minLength":1,"maxLength":1000}
      }
    },
    "outcomeSuggestion":{
      "type":"object","additionalProperties":false,
      "required":["record_id","relationship","rationale"],
      "properties":{
        "record_id":{"type":"string","minLength":1,"maxLength":256},
        "relationship":{"enum":["derived_from","relates_to"]},
        "rationale":{"type":"string","minLength":1,"maxLength":1000}
      }
    }
  }
}"##;

pub const CHANGE_SUMMARY_QUERY_SCHEMA_JSON: &str = r##"{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"native.change-summary.query.v1",
  "type":"object",
  "additionalProperties":false,
  "required":["selection","scope"],
  "properties":{
    "selection":{
      "type":"object","additionalProperties":false,
      "required":["schema","source_event_ids"],
      "properties":{
        "schema":{"const":"native.change-summary.selection.v1"},
        "source_event_ids":{
          "type":"array","minItems":3,"maxItems":3,"uniqueItems":true,
          "items":{"type":"string","minLength":1,"maxLength":256}
        }
      }
    },
    "scope":{
      "type":"object","additionalProperties":false,
      "required":["schema","context_record_ids"],
      "properties":{
        "schema":{"const":"native.change-summary.scope.v1"},
        "context_record_ids":{
          "type":"array","maxItems":16,"uniqueItems":true,
          "items":{"type":"string","minLength":1,"maxLength":256}
        }
      }
    }
  }
}"##;

pub const CHANGE_SUMMARY_OUTPUT_SCHEMA_JSON: &str = r##"{
  "$schema":"https://json-schema.org/draft/2020-12/schema",
  "$id":"native.change-summary.markdown.v1",
  "type":"object",
  "additionalProperties":false,
  "required":["body","renderer"],
  "properties":{
    "body":{"type":"string","minLength":1,"maxLength":131072},
    "renderer":{
      "type":"object","additionalProperties":false,
      "required":["id","revision","spec_sha256"],
      "properties":{
        "id":{"const":"native.change-summary.markdown.renderer"},
        "revision":{"const":"1"},
        "spec_sha256":{"const":"110924767e9186810bb4bc9a08a8807ce78dfc6f7e7e24ffe9d8f075284b2c0d"}
      }
    }
  }
}"##;

pub fn change_summary_result_schema() -> Value {
    serde_json::from_str(CHANGE_SUMMARY_RESULT_SCHEMA_JSON)
        .expect("checked-in change-summary result schema is valid JSON")
}

pub fn change_summary_query_schema() -> Value {
    serde_json::from_str(CHANGE_SUMMARY_QUERY_SCHEMA_JSON)
        .expect("checked-in change-summary query schema is valid JSON")
}

pub fn change_summary_output_schema() -> Value {
    serde_json::from_str(CHANGE_SUMMARY_OUTPUT_SCHEMA_JSON)
        .expect("checked-in change-summary output schema is valid JSON")
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummary {
    pub schema: String,
    pub effective_work_interval: ChangeSummaryEffectiveWorkInterval,
    pub renderer: ChangeSummaryRendererIdentity,
    pub source_groups: Vec<ChangeSummarySourceGroup>,
    pub title: String,
    pub overview: String,
    pub items: Vec<ChangeSummaryItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryItem {
    pub heading: String,
    pub summary: String,
    pub citations: Vec<ChangeSummaryCitation>,
    pub materiality: ChangeSummaryMateriality,
    pub link_suggestions: ChangeSummaryLinkSuggestions,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryMateriality {
    pub summary: String,
    pub references: Vec<ChangeSummaryMaterialityReference>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryMaterialityReference {
    pub record_id: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryLinkSuggestions {
    pub work_items: Vec<ChangeSummaryLinkSuggestion>,
    pub outcomes: Vec<ChangeSummaryLinkSuggestion>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryLinkSuggestion {
    pub record_id: String,
    pub relationship: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryEffectiveWorkInterval {
    pub started_at: String,
    pub ended_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryRendererIdentity {
    pub id: String,
    pub revision: String,
    pub spec_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryCitation {
    pub ordinal: u32,
    pub input_role: String,
    pub input_kind: String,
    pub portable_id: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummarySourceGroup {
    pub run_key: String,
    pub source_ordinal: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSummaryManifestInput {
    pub ordinal: u32,
    pub input_role: String,
    pub input_kind: String,
    pub portable_id: String,
    pub sha256: String,
    pub record_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSummaryInputManifest {
    pub inputs: Vec<ChangeSummaryManifestInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalChangeSummaryResult {
    pub result: ChangeSummary,
    pub canonical_json: String,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryQuery {
    pub selection: ChangeSummarySelection,
    pub scope: ChangeSummaryScope,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummarySelection {
    pub schema: String,
    pub source_event_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeSummaryScope {
    pub schema: String,
    pub context_record_ids: Vec<String>,
}

impl ChangeSummaryQuery {
    /// Canonicalize caller order while refusing duplicate or unavailable
    /// identities. Source events are ordered by their authoritative sequence;
    /// context records are ordered by portable id.
    pub fn canonical<R: ChangeSummaryResolver>(
        source_event_ids: Vec<String>,
        context_record_ids: Vec<String>,
        resolver: &R,
    ) -> Result<Self> {
        let query = Self {
            selection: ChangeSummarySelection::canonical(source_event_ids, resolver)?,
            scope: ChangeSummaryScope::canonical(context_record_ids, resolver)?,
        };
        validate_change_summary_query(&query, resolver)?;
        Ok(query)
    }
}

impl ChangeSummarySelection {
    pub fn canonical<R: ChangeSummaryResolver>(
        source_event_ids: Vec<String>,
        resolver: &R,
    ) -> Result<Self> {
        if source_event_ids.len() != 3 {
            return Err(Error::engine(
                "change-summary selection must name exactly three source events",
            ));
        }
        let mut resolved = Vec::with_capacity(3);
        let mut ids = HashSet::new();
        for event_id in source_event_ids {
            canonical_id("source event id", &event_id)?;
            if !ids.insert(event_id.clone()) {
                return Err(Error::engine(
                    "change-summary source event ids must be unique",
                ));
            }
            let event = resolver
                .source_event(&event_id)?
                .ok_or_else(|| Error::engine("change-summary source event is unavailable"))?;
            if event.event_id != event_id {
                return Err(Error::engine(
                    "change-summary resolver returned a different source event",
                ));
            }
            resolved.push(event);
        }
        resolved.sort_by_key(|event| event.event_seq);
        let selection = Self {
            schema: CHANGE_SUMMARY_SELECTION_SCHEMA.into(),
            source_event_ids: resolved.into_iter().map(|event| event.event_id).collect(),
        };
        validate_selection(&selection, resolver)?;
        Ok(selection)
    }
}

impl ChangeSummaryScope {
    pub fn canonical<R: ChangeSummaryResolver>(
        mut context_record_ids: Vec<String>,
        resolver: &R,
    ) -> Result<Self> {
        if context_record_ids.len() > MAX_CHANGE_SUMMARY_CONTEXT_RECORDS {
            return Err(Error::engine("change-summary context scope is invalid"));
        }
        for record_id in &context_record_ids {
            canonical_id("context record id", record_id)?;
        }
        context_record_ids.sort();
        if context_record_ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::engine(
                "change-summary context record ids must be unique",
            ));
        }
        let scope = Self {
            schema: CHANGE_SUMMARY_SCOPE_SCHEMA.into(),
            context_record_ids,
        };
        validate_scope(&scope, resolver)?;
        Ok(scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSummarySourceEvent {
    pub event_id: String,
    pub event_seq: i64,
    pub run_key: String,
    pub sha256: String,
    pub record_id: String,
    pub record_type: String,
    pub record_kind: String,
    pub record_is_live: bool,
    pub audience_can_view: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChangeSummaryContextRecord {
    pub record_id: String,
    pub record_type: String,
    pub record_kind: String,
    pub record_is_live: bool,
    pub audience_can_view: bool,
    pub is_realised: bool,
    pub current_body_event_id: String,
    pub current_body_sha256: String,
}

/// Verified evidence from one authoritative semantic snapshot.
///
/// A storage adapter must derive these values itself; caller-authored type,
/// kind, liveness, body-head, digest, or audience booleans are not admissible.
/// `audience_can_view` means every principal in the derivation's complete
/// pinned audience can view the record in this same snapshot. Keeping this
/// seam synchronous lets an adapter pre-resolve evidence inside its existing
/// transaction and hand the validator an immutable snapshot value.
pub trait ChangeSummaryResolver {
    fn source_event(&self, event_id: &str) -> Result<Option<ChangeSummarySourceEvent>>;
    fn context_record(&self, record_id: &str) -> Result<Option<ChangeSummaryContextRecord>>;
}

fn schema_validator(schema: &Value, label: &str) -> Result<jsonschema::Validator> {
    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .build(schema)
        .map_err(|_| Error::engine(format!("change-summary {label} schema is invalid")))
}

pub fn validate_change_summary_result_schema(value: &Value) -> Result<()> {
    schema_validator(&change_summary_result_schema(), "result")?
        .validate(value)
        .map_err(|_| {
            Error::engine("change-summary result does not satisfy native.change-summary.v1")
        })
}

fn canonical_text(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.trim() != value
        || value
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        return Err(Error::engine(format!(
            "change-summary {label} must be nonblank, trimmed text without non-whitespace control characters"
        )));
    }
    Ok(())
}

fn canonical_id(label: &str, value: &str) -> Result<()> {
    canonical_text(label, value)?;
    if value.contains('`') || value.chars().any(char::is_whitespace) {
        return Err(Error::engine(format!(
            "change-summary {label} cannot contain whitespace or backticks"
        )));
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_run_key(value: &str) -> Result<()> {
    match crate::runkey::validate_full(Some(value)) {
        crate::runkey::KeyOutcome::Valid(valid) if valid == value => Ok(()),
        _ => Err(Error::engine(
            "change-summary source run key is not a valid full run key",
        )),
    }
}

fn validate_source_evidence(event: &ChangeSummarySourceEvent) -> Result<()> {
    canonical_id("source event id", &event.event_id)?;
    canonical_id("source record id", &event.record_id)?;
    canonical_text("source record type", &event.record_type)?;
    canonical_text("source record kind", &event.record_kind)?;
    validate_run_key(&event.run_key)?;
    if event.event_seq <= 0
        || !valid_sha256(&event.sha256)
        || !event.record_is_live
        || !event.audience_can_view
    {
        return Err(Error::engine(
            "change-summary source evidence is unavailable to the complete audience",
        ));
    }
    Ok(())
}

fn validate_context_evidence(record: &ChangeSummaryContextRecord) -> Result<()> {
    canonical_id("context record id", &record.record_id)?;
    canonical_text("context record type", &record.record_type)?;
    canonical_text("context record kind", &record.record_kind)?;
    canonical_id("context body event id", &record.current_body_event_id)?;
    if !valid_sha256(&record.current_body_sha256)
        || !record.record_is_live
        || !record.audience_can_view
    {
        return Err(Error::engine(
            "change-summary context evidence is unavailable to the complete audience",
        ));
    }
    Ok(())
}

fn require_context<R: ChangeSummaryResolver>(
    resolver: &R,
    scope: &ChangeSummaryScope,
    record_id: &str,
) -> Result<ChangeSummaryContextRecord> {
    if scope
        .context_record_ids
        .binary_search_by(|candidate| candidate.as_str().cmp(record_id))
        .is_err()
    {
        return Err(Error::engine(
            "change-summary reference is outside its canonical context scope",
        ));
    }
    let record = resolver
        .context_record(record_id)?
        .ok_or_else(|| Error::engine("change-summary context record is unavailable"))?;
    validate_context_evidence(&record)?;
    if record.record_id != record_id {
        return Err(Error::engine(
            "change-summary resolver returned a different context record",
        ));
    }
    Ok(record)
}

fn validate_interval(interval: &ChangeSummaryEffectiveWorkInterval) -> Result<()> {
    let started = chrono::DateTime::parse_from_rfc3339(&interval.started_at)
        .map_err(|_| Error::engine("change-summary work interval start is invalid"))?;
    let ended = chrono::DateTime::parse_from_rfc3339(&interval.ended_at)
        .map_err(|_| Error::engine("change-summary work interval end is invalid"))?;
    let canonical = |value: chrono::DateTime<chrono::FixedOffset>| {
        value
            .with_timezone(&chrono::Utc)
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    };
    if canonical(started) != interval.started_at || canonical(ended) != interval.ended_at {
        return Err(Error::engine(
            "change-summary work interval must use canonical UTC millisecond timestamps",
        ));
    }
    let duration = ended.signed_duration_since(started).num_seconds();
    if duration <= 0 || duration > MAX_EFFECTIVE_WORK_INTERVAL_SECONDS {
        return Err(Error::engine(
            "change-summary work interval must be positive and no longer than 366 days",
        ));
    }
    Ok(())
}

fn validate_renderer_identity(renderer: &ChangeSummaryRendererIdentity) -> Result<()> {
    if renderer.id != super::render::CHANGE_SUMMARY_RENDERER_ID
        || renderer.revision != super::render::CHANGE_SUMMARY_RENDERER_REVISION
        || renderer.spec_sha256 != super::render::CHANGE_SUMMARY_RENDERER_SHA256
    {
        return Err(Error::engine(
            "change-summary renderer identity does not match its pinned recipe",
        ));
    }
    Ok(())
}

fn validate_selection<R: ChangeSummaryResolver>(
    selection: &ChangeSummarySelection,
    resolver: &R,
) -> Result<()> {
    if selection.schema != CHANGE_SUMMARY_SELECTION_SCHEMA || selection.source_event_ids.len() != 3
    {
        return Err(Error::engine(
            "change-summary selection must name exactly three source events",
        ));
    }
    let mut event_ids = HashSet::new();
    let mut run_keys = HashSet::new();
    let mut previous_seq: Option<i64> = None;
    for event_id in &selection.source_event_ids {
        canonical_id("source event id", event_id)?;
        if !event_ids.insert(event_id.as_str()) {
            return Err(Error::engine(
                "change-summary source event ids must be unique",
            ));
        }
        let event = resolver
            .source_event(event_id)?
            .ok_or_else(|| Error::engine("change-summary source event is unavailable"))?;
        validate_source_evidence(&event)?;
        if event.event_id != *event_id {
            return Err(Error::engine(
                "change-summary source event resolution is invalid",
            ));
        }
        if !run_keys.insert(event.run_key) {
            return Err(Error::engine(
                "change-summary source events must belong to distinct runs",
            ));
        }
        if previous_seq.is_some_and(|prior| prior >= event.event_seq) {
            return Err(Error::engine(
                "change-summary source events must be in authoritative event order",
            ));
        }
        previous_seq = Some(event.event_seq);
    }
    Ok(())
}

fn validate_scope<R: ChangeSummaryResolver>(
    scope: &ChangeSummaryScope,
    resolver: &R,
) -> Result<()> {
    if scope.schema != CHANGE_SUMMARY_SCOPE_SCHEMA
        || scope.context_record_ids.len() > MAX_CHANGE_SUMMARY_CONTEXT_RECORDS
    {
        return Err(Error::engine("change-summary context scope is invalid"));
    }
    let mut previous: Option<&str> = None;
    for record_id in &scope.context_record_ids {
        canonical_id("context record id", record_id)?;
        if previous.is_some_and(|prior| prior >= record_id.as_str()) {
            return Err(Error::engine(
                "change-summary context record ids must be sorted and unique",
            ));
        }
        previous = Some(record_id);
        require_context(resolver, scope, record_id)?;
    }
    Ok(())
}

pub fn validate_change_summary_query<R: ChangeSummaryResolver>(
    query: &ChangeSummaryQuery,
    resolver: &R,
) -> Result<()> {
    let value = serde_json::to_value(query)?;
    schema_validator(&change_summary_query_schema(), "query")?
        .validate(&value)
        .map_err(|_| Error::engine("change-summary query does not satisfy its pinned contract"))?;
    validate_selection(&query.selection, resolver)?;
    validate_scope(&query.scope, resolver)
}

pub fn validate_change_summary_manifest<R: ChangeSummaryResolver>(
    query: &ChangeSummaryQuery,
    manifest: &ChangeSummaryInputManifest,
    resolver: &R,
) -> Result<()> {
    validate_change_summary_query(query, resolver)?;
    if manifest.inputs.len() < 3 || manifest.inputs.len() > MAX_CHANGE_SUMMARY_INPUTS {
        return Err(Error::engine(
            "change-summary input manifest is not bounded",
        ));
    }
    let mut source_ids = Vec::new();
    let mut context_ids = Vec::new();
    for (index, input) in manifest.inputs.iter().enumerate() {
        if input.ordinal as usize != index {
            return Err(Error::engine(
                "change-summary manifest ordinals must be contiguous and canonical",
            ));
        }
        canonical_id("manifest portable id", &input.portable_id)?;
        canonical_id("manifest record id", &input.record_id)?;
        if !valid_sha256(&input.sha256) {
            return Err(Error::engine(
                "change-summary manifest digest must be lowercase sha256",
            ));
        }
        match (input.input_role.as_str(), input.input_kind.as_str()) {
            ("source", "content_event") if index < 3 => {
                let event = resolver
                    .source_event(&input.portable_id)?
                    .ok_or_else(|| Error::engine("change-summary source event is unavailable"))?;
                validate_source_evidence(&event)?;
                if event.event_id != input.portable_id
                    || event.sha256 != input.sha256
                    || event.record_id != input.record_id
                {
                    return Err(Error::engine(
                        "change-summary source manifest input does not match authoritative evidence",
                    ));
                }
                source_ids.push(input.portable_id.clone());
            }
            ("context", "record_body") if index >= 3 => {
                let record = require_context(resolver, &query.scope, &input.record_id)?;
                if record.current_body_event_id != input.portable_id
                    || record.current_body_sha256 != input.sha256
                {
                    return Err(Error::engine(
                        "change-summary context manifest input is not the current authoritative body",
                    ));
                }
                context_ids.push(input.record_id.clone());
            }
            _ => {
                return Err(Error::engine(
                    "change-summary manifest must contain three source events followed by context bodies",
                ))
            }
        }
    }
    if source_ids != query.selection.source_event_ids
        || context_ids != query.scope.context_record_ids
    {
        return Err(Error::engine(
            "change-summary manifest does not exactly cover its canonical query",
        ));
    }
    Ok(())
}

fn citation_matches(input: &ChangeSummaryManifestInput, citation: &ChangeSummaryCitation) -> bool {
    citation.ordinal == input.ordinal
        && citation.input_role == input.input_role
        && citation.input_kind == input.input_kind
        && citation.portable_id == input.portable_id
        && citation.sha256 == input.sha256
}

fn cited_context(
    citations: &[ChangeSummaryCitation],
    manifest: &ChangeSummaryInputManifest,
    record_id: &str,
) -> bool {
    manifest.inputs.iter().any(|input| {
        input.input_role == "context"
            && input.record_id == record_id
            && citations
                .iter()
                .any(|citation| citation_matches(input, citation))
    })
}

fn validate_suggestions<R: ChangeSummaryResolver>(
    label: &str,
    suggestions: &[ChangeSummaryLinkSuggestion],
    query: &ChangeSummaryQuery,
    manifest: &ChangeSummaryInputManifest,
    citations: &[ChangeSummaryCitation],
    resolver: &R,
    relationships: &[&str],
) -> Result<()> {
    let mut previous: Option<(&str, &str)> = None;
    for suggestion in suggestions {
        canonical_id(&format!("{label} record id"), &suggestion.record_id)?;
        canonical_text(
            &format!("{label} suggestion rationale"),
            &suggestion.rationale,
        )?;
        if !relationships.contains(&suggestion.relationship.as_str()) {
            return Err(Error::engine(format!(
                "change-summary {label} relationship is unsupported"
            )));
        }
        let key = (
            suggestion.record_id.as_str(),
            suggestion.relationship.as_str(),
        );
        if previous.is_some_and(|prior| prior >= key) {
            return Err(Error::engine(format!(
                "change-summary {label} suggestions must be sorted and unique"
            )));
        }
        previous = Some(key);
        let record = require_context(resolver, &query.scope, &suggestion.record_id)?;
        let type_matches = match label {
            "WorkItem" => record.record_type == "WorkItem",
            "Outcome" => {
                record.record_type == "Outcome"
                    && record.record_kind == "impact"
                    && record.is_realised
            }
            _ => false,
        };
        if !type_matches {
            return Err(Error::engine(format!(
                "change-summary {label} suggestion has the wrong governed record identity"
            )));
        }
        if !cited_context(citations, manifest, &suggestion.record_id) {
            return Err(Error::engine(format!(
                "change-summary {label} suggestion lacks an exact context citation"
            )));
        }
    }
    Ok(())
}

/// Sort every structural set into its portable order without changing prose.
/// Duplicate semantic identities are rejected rather than silently coalesced.
pub fn canonicalize_change_summary_result(mut summary: ChangeSummary) -> Result<ChangeSummary> {
    validate_change_summary_result_schema(&serde_json::to_value(&summary)?)?;
    let item = summary
        .items
        .first_mut()
        .ok_or_else(|| Error::engine("change-summary result must contain exactly one item"))?;
    item.citations.sort_by_key(|citation| citation.ordinal);
    if item
        .citations
        .windows(2)
        .any(|pair| pair[0].ordinal == pair[1].ordinal)
    {
        return Err(Error::engine(
            "change-summary citations contain duplicate manifest ordinals",
        ));
    }
    item.materiality
        .references
        .sort_by(|left, right| left.record_id.cmp(&right.record_id));
    if item
        .materiality
        .references
        .windows(2)
        .any(|pair| pair[0].record_id == pair[1].record_id)
    {
        return Err(Error::engine(
            "change-summary materiality references contain duplicate record ids",
        ));
    }
    let sort_suggestions = |values: &mut Vec<ChangeSummaryLinkSuggestion>| -> Result<()> {
        values.sort_by(|left, right| {
            (&left.record_id, &left.relationship).cmp(&(&right.record_id, &right.relationship))
        });
        if values.windows(2).any(|pair| {
            pair[0].record_id == pair[1].record_id && pair[0].relationship == pair[1].relationship
        }) {
            return Err(Error::engine(
                "change-summary link suggestions contain duplicate identities",
            ));
        }
        Ok(())
    };
    sort_suggestions(&mut item.link_suggestions.work_items)?;
    sort_suggestions(&mut item.link_suggestions.outcomes)?;
    summary
        .source_groups
        .sort_by_key(|group| group.source_ordinal);
    let mut run_keys = HashSet::new();
    if summary
        .source_groups
        .windows(2)
        .any(|pair| pair[0].source_ordinal == pair[1].source_ordinal)
        || summary
            .source_groups
            .iter()
            .any(|group| !run_keys.insert(group.run_key.clone()))
    {
        return Err(Error::engine(
            "change-summary source groups contain duplicate ordinals or run keys",
        ));
    }
    Ok(summary)
}

pub fn validate_change_summary<R: ChangeSummaryResolver>(
    summary: &ChangeSummary,
    query: &ChangeSummaryQuery,
    manifest: &ChangeSummaryInputManifest,
    resolver: &R,
) -> Result<()> {
    validate_change_summary_result_schema(&serde_json::to_value(summary)?)?;
    validate_change_summary_manifest(query, manifest, resolver)?;
    if summary.schema != CHANGE_SUMMARY_RESULT_SCHEMA || summary.items.len() != 1 {
        return Err(Error::engine("change-summary result identity is invalid"));
    }
    validate_interval(&summary.effective_work_interval)?;
    validate_renderer_identity(&summary.renderer)?;
    canonical_text("title", &summary.title)?;
    canonical_text("overview", &summary.overview)?;
    let item = &summary.items[0];
    canonical_text("item heading", &item.heading)?;
    canonical_text("item summary", &item.summary)?;
    canonical_text("materiality summary", &item.materiality.summary)?;

    let mut cited_source_ordinals = HashSet::new();
    let mut previous_ordinal: Option<u32> = None;
    for citation in &item.citations {
        if previous_ordinal.is_some_and(|prior| prior >= citation.ordinal) {
            return Err(Error::engine(
                "change-summary citations must be sorted and unique",
            ));
        }
        previous_ordinal = Some(citation.ordinal);
        let input = manifest
            .inputs
            .get(citation.ordinal as usize)
            .ok_or_else(|| {
                Error::engine("change-summary citation ordinal is outside the manifest")
            })?;
        if !citation_matches(input, citation) {
            return Err(Error::engine(
                "change-summary citation does not exactly match its immutable manifest input",
            ));
        }
        if input.input_role == "source" {
            cited_source_ordinals.insert(citation.ordinal);
        }
    }
    if cited_source_ordinals != HashSet::from([0, 1, 2]) {
        return Err(Error::engine(
            "change-summary item must cite all three authoritative source inputs",
        ));
    }

    if summary.source_groups.len() != 3 {
        return Err(Error::engine(
            "change-summary result must expose exactly three source run groups",
        ));
    }
    let mut grouped = HashSet::new();
    let mut grouped_runs = HashSet::new();
    let mut previous_group: Option<u32> = None;
    for group in &summary.source_groups {
        if previous_group.is_some_and(|prior| prior >= group.source_ordinal)
            || !grouped.insert(group.source_ordinal)
            || !grouped_runs.insert(group.run_key.as_str())
        {
            return Err(Error::engine(
                "change-summary source groups must be sorted and unique",
            ));
        }
        previous_group = Some(group.source_ordinal);
        let input = manifest
            .inputs
            .get(group.source_ordinal as usize)
            .filter(|input| input.input_role == "source")
            .ok_or_else(|| {
                Error::engine("change-summary source group does not name a source input")
            })?;
        if !item
            .citations
            .iter()
            .any(|citation| citation_matches(input, citation))
        {
            return Err(Error::engine(
                "change-summary source group is not bound to an item citation",
            ));
        }
        let evidence = resolver
            .source_event(&input.portable_id)?
            .ok_or_else(|| Error::engine("change-summary source event is unavailable"))?;
        validate_run_key(&group.run_key)?;
        if evidence.run_key != group.run_key {
            return Err(Error::engine(
                "change-summary source group run key does not match authoritative evidence",
            ));
        }
    }
    if grouped != HashSet::from([0, 1, 2]) {
        return Err(Error::engine(
            "change-summary source groups must cover all three source inputs",
        ));
    }

    let mut previous_reference: Option<&str> = None;
    for reference in &item.materiality.references {
        canonical_id("materiality reference id", &reference.record_id)?;
        canonical_text("materiality rationale", &reference.rationale)?;
        if previous_reference.is_some_and(|prior| prior >= reference.record_id.as_str()) {
            return Err(Error::engine(
                "change-summary materiality references must be sorted and unique",
            ));
        }
        previous_reference = Some(&reference.record_id);
        require_context(resolver, &query.scope, &reference.record_id)?;
        if !cited_context(&item.citations, manifest, &reference.record_id) {
            return Err(Error::engine(
                "change-summary materiality reference lacks an exact context citation",
            ));
        }
    }
    validate_suggestions(
        "WorkItem",
        &item.link_suggestions.work_items,
        query,
        manifest,
        &item.citations,
        resolver,
        &["derived_from", "implements", "relates_to"],
    )?;
    validate_suggestions(
        "Outcome",
        &item.link_suggestions.outcomes,
        query,
        manifest,
        &item.citations,
        resolver,
        &["derived_from", "relates_to"],
    )?;
    super::render::render_change_summary_output(summary)?;
    Ok(())
}

pub fn canonicalize_and_validate_change_summary<R: ChangeSummaryResolver>(
    value: &Value,
    query: &ChangeSummaryQuery,
    manifest: &ChangeSummaryInputManifest,
    resolver: &R,
) -> Result<CanonicalChangeSummaryResult> {
    validate_change_summary_result_schema(value)?;
    let summary = canonicalize_change_summary_result(serde_json::from_value(value.clone())?)?;
    validate_change_summary(&summary, query, manifest, resolver)?;
    let canonical_json = String::from_utf8(crate::derivation::canonical_json(
        &serde_json::to_value(&summary)?,
    ))
    .expect("canonical change-summary JSON is UTF-8");
    let sha256 = format!("{:x}", Sha256::digest(canonical_json.as_bytes()));
    Ok(CanonicalChangeSummaryResult {
        result: summary,
        canonical_json,
        sha256,
    })
}

pub fn decode_and_validate_change_summary<R: ChangeSummaryResolver>(
    value: &Value,
    query: &ChangeSummaryQuery,
    manifest: &ChangeSummaryInputManifest,
    resolver: &R,
) -> Result<ChangeSummary> {
    Ok(canonicalize_and_validate_change_summary(value, query, manifest, resolver)?.result)
}
