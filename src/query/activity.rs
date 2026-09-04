//! Canonical event-level activity selection over a caller-authorized record set.
//!
//! The caller supplies membership resolved at the pinned window end. This
//! module folds the content prefix once, evaluates shallow typed action clauses
//! at each event, and only then applies caller-visible event-count paging.

use std::collections::{BTreeSet, HashMap, HashSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::Row;

use crate::db::Db;
use crate::error::Result;
use crate::events::EventRow;

use super::error::contract_violation;

pub const DEFAULT_ACTIVITY_LIMIT: i64 = 200;
pub const MAX_ACTIVITY_LIMIT: i64 = 1000;

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActivityArgs {
    /// Exclusive database-local event cursor; defaults to zero.
    #[serde(alias = "after_seq")]
    pub after_local_seq: Option<i64>,
    /// Pinned database-local content head; omit on the first page.
    #[serde(alias = "through_seq")]
    pub through_local_seq: Option<i64>,
    /// Optional exact account-token filter.
    pub actors: Option<ActorPredicate>,
    pub actions: Actions,
    /// Authorized matching-event limit; defaults to 200.
    #[schemars(range(min = 1, max = 1000))]
    pub limit: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ActorPredicate {
    #[schemars(length(min = 1))]
    pub accounts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Actions {
    /// OR clauses; populated fields within a clause are ANDed.
    #[schemars(with = "Vec<ActionClauseSchema>")]
    #[schemars(length(min = 1))]
    pub any: Vec<ActionClause>,
}

#[allow(dead_code)]
#[derive(JsonSchema)]
#[serde(rename_all = "snake_case")]
enum ActivityActionKindSchema {
    Event,
    FieldTransition,
    FacetTransition,
    LinkChange,
}

/// Compact descriptor shape. Runtime deserialization still uses the strict
/// tagged [`ActionClause`] enum below, which enforces fields by action kind.
#[allow(dead_code)]
#[derive(JsonSchema)]
struct ActionClauseSchema {
    /// `event`: event_* and changed_fields_*; `field_transition`: field,
    /// from/to/to_terminality; `facet_transition`: key plus those transition
    /// fields; `link_change`: change/relationship/direction.
    kind: ActivityActionKindSchema,
    event_types: Option<Vec<String>>,
    event_families: Option<Vec<String>>,
    changed_fields_any: Option<Vec<String>>,
    changed_fields_all: Option<Vec<String>>,
    field: Option<String>,
    key: Option<String>,
    r#from: Option<MatchValue>,
    to: Option<MatchValue>,
    to_terminality: Option<Terminality>,
    change: Option<LinkChangeKind>,
    relationship: Option<String>,
    direction: Option<LinkDirection>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionClause {
    Event {
        event_types: Option<Vec<String>>,
        event_families: Option<Vec<String>>,
        changed_fields_any: Option<Vec<String>>,
        changed_fields_all: Option<Vec<String>>,
    },
    FieldTransition {
        field: String,
        #[serde(default, rename = "from")]
        from_value: MatchValue,
        #[serde(default, rename = "to")]
        to_value: MatchValue,
        to_terminality: Option<Terminality>,
    },
    FacetTransition {
        key: String,
        #[serde(default, rename = "from")]
        from_value: MatchValue,
        #[serde(default, rename = "to")]
        to_value: MatchValue,
        to_terminality: Option<Terminality>,
    },
    LinkChange {
        change: Option<LinkChangeKind>,
        relationship: Option<String>,
        direction: Option<LinkDirection>,
    },
}

/// Distinguishes an omitted constraint from an explicit JSON null (absence).
/// Its public schema is the unconstrained JSON value at the `from`/`to` site;
/// the wrapper exists only for serde presence tracking.
#[derive(Clone, Debug, Default)]
pub struct MatchValue {
    specified: bool,
    value: Value,
}

impl<'de> Deserialize<'de> for MatchValue {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if !value.is_string() && !value.is_number() && !value.is_null() {
            return Err(serde::de::Error::custom(
                "activity transition values must be a string, number, or null",
            ));
        }
        Ok(Self {
            specified: true,
            value,
        })
    }
}

impl JsonSchema for MatchValue {
    fn schema_name() -> String {
        "ActivityTransitionValue".into()
    }

    fn is_referenceable() -> bool {
        false
    }

    fn json_schema(generator: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        let _ = generator;
        let mut schema = schemars::schema::SchemaObject::default();
        schema.instance_type = Some(schemars::schema::SingleOrVec::Vec(vec![
            schemars::schema::InstanceType::String,
            schemars::schema::InstanceType::Number,
            schemars::schema::InstanceType::Null,
        ]));
        schemars::schema::Schema::Object(schema)
    }
}

impl MatchValue {
    fn matches(&self, actual: &Value) -> bool {
        if !self.specified || self.value == *actual {
            return true;
        }
        let Some(wanted) = self.value.as_f64() else {
            return false;
        };
        let actual = actual
            .as_f64()
            .or_else(|| actual.as_str()?.parse::<f64>().ok());
        actual == Some(wanted)
    }

    fn specified_str(&self) -> Option<&str> {
        self.specified.then(|| self.value.as_str()).flatten()
    }
}

impl ActionClause {
    /// Record identities used as exact transition selectors. The tool layer
    /// authorizes these before execution just like home/owner filter roots.
    pub fn reference_selectors(&self) -> impl Iterator<Item = &str> {
        let values = match self {
            Self::FieldTransition {
                field,
                from_value,
                to_value,
                ..
            } if matches!(field.as_str(), "home_id" | "owner_id") => {
                [from_value.specified_str(), to_value.specified_str()]
            }
            _ => [None, None],
        };
        values.into_iter().flatten()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Terminality {
    Open,
    TerminalPositive,
    TerminalNegative,
}

impl Terminality {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::TerminalPositive => "terminal_positive",
            Self::TerminalNegative => "terminal_negative",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkChangeKind {
    Added,
    Removed,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkDirection {
    Out,
    In,
    Both,
}

#[derive(Debug, Serialize)]
pub struct ActivityItem {
    pub event: Value,
    pub matches: Vec<Value>,
}

#[derive(Debug, Serialize)]
pub struct ActivityPage {
    pub shape: &'static str,
    pub activities: Vec<ActivityItem>,
    pub matched_event_count: usize,
    pub high_water_local_seq: i64,
    pub subject_as_of_local_seq: i64,
    pub has_more: bool,
}

#[derive(Default)]
struct TransitionState {
    fields: HashMap<(String, String), Value>,
    facets: HashMap<(String, String), GovernedValue>,
}

impl TransitionState {
    fn field_str(&self, record_id: &str, field: &str) -> Option<&str> {
        self.fields
            .get(&(record_id.to_string(), field.to_string()))
            .and_then(Value::as_str)
    }
}

#[derive(Clone, Debug)]
struct GovernedValue {
    value: Value,
    vocab_ref: Option<String>,
}

impl Default for GovernedValue {
    fn default() -> Self {
        Self {
            value: Value::Null,
            vocab_ref: None,
        }
    }
}

#[derive(Clone, Debug)]
struct FacetTransitionEvidence {
    key: String,
    before: GovernedValue,
    after: GovernedValue,
}

#[derive(Default)]
struct TerminalityIndex {
    by_vocabulary: HashMap<(String, String), String>,
}

impl TerminalityIndex {
    fn get<'a>(&'a self, value: &GovernedValue) -> Option<&'a str> {
        let vocabulary = crate::meta::resolve_vocab_ref(value.vocab_ref.as_deref()?);
        let token = value.value.as_str()?;
        self.by_vocabulary
            .get(&(vocabulary.to_string(), token.to_string()))
            .map(String::as_str)
    }
}

struct MatchContext<'a> {
    event: &'a EventRow,
    payload: &'a Value,
    subjects: &'a HashSet<String>,
    state: &'a TransitionState,
    schema_rows: &'a [crate::query::cascade::SchemaConfigRow],
    fields: &'a HashMap<String, (Value, Value)>,
    facet: &'a Option<FacetTransitionEvidence>,
    terminalities: &'a TerminalityIndex,
}

pub fn validate(args: &ActivityArgs) -> Result<()> {
    if args.after_local_seq.is_some_and(|seq| seq < 0) {
        return Err(contract_violation(
            "query_record activity after_local_seq must be >= 0",
        ));
    }
    if args.through_local_seq.is_some_and(|seq| seq < 0) {
        return Err(contract_violation(
            "query_record activity through_local_seq must be >= 0",
        ));
    }
    let limit = args.limit.unwrap_or(DEFAULT_ACTIVITY_LIMIT);
    if !(1..=MAX_ACTIVITY_LIMIT).contains(&limit) {
        return Err(contract_violation(format!(
            "query_record activity limit must be between 1 and {MAX_ACTIVITY_LIMIT}"
        )));
    }
    if args.actions.any.is_empty() {
        return Err(contract_violation(
            "query_record activity actions.any must not be empty",
        ));
    }
    if args
        .actors
        .as_ref()
        .is_some_and(|actors| actors.accounts.is_empty())
    {
        return Err(contract_violation(
            "query_record activity actors.accounts must not be empty",
        ));
    }
    for (index, clause) in args.actions.any.iter().enumerate() {
        validate_clause(index, clause)?;
    }
    Ok(())
}

fn validate_clause(index: usize, clause: &ActionClause) -> Result<()> {
    let empty = |name: &str, values: &Option<Vec<String>>| {
        values.as_ref().is_some_and(Vec::is_empty).then(|| {
            contract_violation(format!(
                "query_record activity clause {index} {name} must not be empty"
            ))
        })
    };
    match clause {
        ActionClause::Event {
            event_types,
            event_families,
            changed_fields_any,
            changed_fields_all,
        } => {
            for (name, values) in [
                ("event_types", event_types),
                ("event_families", event_families),
                ("changed_fields_any", changed_fields_any),
                ("changed_fields_all", changed_fields_all),
            ] {
                if let Some(error) = empty(name, values) {
                    return Err(error);
                }
            }
            if event_types.is_none()
                && event_families.is_none()
                && changed_fields_any.is_none()
                && changed_fields_all.is_none()
            {
                return Err(contract_violation(format!(
                    "query_record activity event clause {index} needs at least one constraint"
                )));
            }
            if let Some(types) = event_types {
                if let Some(unknown) = types
                    .iter()
                    .find(|event_type| !crate::events::EVENT_TYPES.contains(&event_type.as_str()))
                {
                    return Err(contract_violation(format!(
                        "query_record activity clause {index} has unknown event type '{unknown}'"
                    )));
                }
            }
            const FAMILIES: [&str; 7] = [
                "annotations",
                "created",
                "deleted",
                "facets",
                "links",
                "moved",
                "updated",
            ];
            if let Some(families) = event_families {
                if let Some(unknown) = families
                    .iter()
                    .find(|family| !FAMILIES.contains(&family.as_str()))
                {
                    return Err(contract_violation(format!(
                        "query_record activity clause {index} has unknown event family '{unknown}'"
                    )));
                }
            }
        }
        ActionClause::FieldTransition {
            field,
            from_value,
            to_value,
            to_terminality,
        } => {
            const FIELDS: [&str; 10] = [
                "body",
                "home_id",
                "kind",
                "lifecycle",
                "maturity",
                "name",
                "owner_id",
                "persistence",
                "summary",
                "type",
            ];
            if !FIELDS.contains(&field.as_str()) {
                return Err(contract_violation(format!(
                    "query_record activity clause {index} has unknown spine field '{field}'"
                )));
            }
            if !from_value.specified && !to_value.specified && to_terminality.is_none() {
                return Err(contract_violation(format!(
                    "query_record activity field_transition clause {index} needs from, to, or to_terminality"
                )));
            }
        }
        ActionClause::FacetTransition {
            key,
            from_value,
            to_value,
            to_terminality,
        } => {
            if key.trim().is_empty() {
                return Err(contract_violation(format!(
                    "query_record activity clause {index} facet key must not be empty"
                )));
            }
            if !from_value.specified && !to_value.specified && to_terminality.is_none() {
                return Err(contract_violation(format!(
                    "query_record activity facet_transition clause {index} needs from, to, or to_terminality"
                )));
            }
        }
        ActionClause::LinkChange {
            change,
            relationship,
            direction,
        } => {
            if relationship
                .as_ref()
                .is_some_and(|value| value.trim().is_empty())
            {
                return Err(contract_violation(format!(
                    "query_record activity clause {index} relationship must not be empty"
                )));
            }
            if change.is_none() && relationship.is_none() && direction.is_none() {
                return Err(contract_violation(format!(
                    "query_record activity link_change clause {index} needs at least one constraint"
                )));
            }
        }
    }
    Ok(())
}

fn parsed_payload(event: &EventRow) -> Result<Value> {
    event
        .payload
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
        .map_err(Into::into)
}

fn classify_event_families(event: &EventRow, payload: &Value) -> BTreeSet<&'static str> {
    let mut families = BTreeSet::new();
    match event.event_type.as_str() {
        "record.created" => {
            families.insert("created");
        }
        "record.updated" => {
            families.insert("updated");
            if payload.get("home_id").is_some() {
                families.insert("moved");
            }
        }
        "record.type_corrected.v1" => {
            families.insert("updated");
        }
        "artifact.source_attested" => {
            families.insert("updated");
        }
        "record.deleted" => {
            families.insert("deleted");
        }
        "facet.set" | "facet.unset" => {
            families.insert("facets");
        }
        "link.added" | "link.removed" => {
            families.insert("links");
        }
        "annotation.target.set" | "annotation.target.removed" => {
            families.insert("annotations");
        }
        _ => {}
    }
    families
}

fn changed_fields(event: &EventRow, payload: &Value) -> BTreeSet<String> {
    match event.event_type.as_str() {
        "record.created" | "record.updated" => payload
            .as_object()
            .into_iter()
            .flat_map(|object| object.keys())
            .filter(|field| {
                matches!(
                    field.as_str(),
                    "body"
                        | "home_id"
                        | "kind"
                        | "lifecycle"
                        | "maturity"
                        | "name"
                        | "owner_id"
                        | "persistence"
                        | "summary"
                        | "type"
                )
            })
            .cloned()
            .collect(),
        "record.type_corrected.v1" => BTreeSet::from(["kind".into(), "type".into()]),
        "facet.set" | "facet.unset" => payload
            .get("key")
            .and_then(Value::as_str)
            .map(|key| BTreeSet::from([format!("facet:{key}")]))
            .unwrap_or_default(),
        _ => BTreeSet::new(),
    }
}

async fn terminality_index_in_pool(pool: &sqlx::SqlitePool) -> Result<TerminalityIndex> {
    let rows = sqlx::query(
        "SELECT vocabulary.id AS vocabulary_id, vocabulary.name AS vocabulary_name,\n\
                v.value, COALESCE(c.terminality, v.terminality) AS terminality\n\
           FROM vocabularies vocabulary\n\
           JOIN vocabulary_values v ON v.vocabulary_id = vocabulary.id\n\
           LEFT JOIN vocabulary_values c ON c.id = v.alias_of\n\
          WHERE (v.alias_of IS NULL AND v.status = 'active')\n\
             OR (v.alias_of IS NOT NULL AND c.status = 'active' AND c.alias_of IS NULL)",
    )
    .fetch_all(pool)
    .await?;
    let mut index = TerminalityIndex::default();
    for row in rows {
        let vocabulary_id: String = row.try_get("vocabulary_id")?;
        let vocabulary_name: String = row.try_get("vocabulary_name")?;
        let value: String = row.try_get("value")?;
        let terminality: String = row.try_get("terminality")?;
        for vocabulary in [vocabulary_id, vocabulary_name] {
            index
                .by_vocabulary
                .insert((vocabulary, value.clone()), terminality.clone());
        }
    }
    Ok(index)
}

fn governing_field_vocabulary(
    schema_rows: &[crate::query::cascade::SchemaConfigRow],
    state: &TransitionState,
    record_id: &str,
    field: &str,
) -> Option<String> {
    let record_type = state.field_str(record_id, "type")?;
    let kind = state.field_str(record_id, "kind");
    let home_id = state.field_str(record_id, "home_id");
    crate::query::cascade::facets_for_record_context(schema_rows, record_type, kind, home_id)
        .get(field)
        .and_then(|shape| shape.get("vocab").or_else(|| shape.get("vocab_ref")))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn transition_values(
    state: &mut TransitionState,
    event: &EventRow,
    payload: &Value,
) -> (
    HashMap<String, (Value, Value)>,
    Option<FacetTransitionEvidence>,
) {
    let mut fields = HashMap::new();
    if matches!(
        event.event_type.as_str(),
        "record.created" | "record.updated"
    ) {
        if let Some(object) = payload.as_object() {
            for (field, after) in object {
                let key = (event.record_id.clone(), field.clone());
                let before = state.fields.get(&key).cloned().unwrap_or(Value::Null);
                fields.insert(field.clone(), (before, after.clone()));
                state.fields.insert(key, after.clone());
            }
        }
    } else if event.event_type == "record.type_corrected.v1" {
        if let Some(to) = payload.get("to").and_then(Value::as_object) {
            for field in ["type", "kind"] {
                if let Some(after) = to.get(field) {
                    let key = (event.record_id.clone(), field.to_string());
                    let before = state.fields.get(&key).cloned().unwrap_or(Value::Null);
                    fields.insert(field.to_string(), (before, after.clone()));
                    state.fields.insert(key, after.clone());
                }
            }
        }
    }
    let facet = match event.event_type.as_str() {
        "facet.set" | "facet.unset"
            if !payload
                .get("observation_only")
                .and_then(Value::as_bool)
                .unwrap_or(false) =>
        {
            payload.get("key").and_then(Value::as_str).map(|key| {
                let state_key = (event.record_id.clone(), key.to_string());
                let before = state.facets.get(&state_key).cloned().unwrap_or_default();
                let after = if event.event_type == "facet.set" {
                    GovernedValue {
                        value: payload.get("value").cloned().unwrap_or(Value::Null),
                        vocab_ref: payload
                            .get("vocab_ref")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                    }
                } else {
                    GovernedValue::default()
                };
                if event.event_type == "facet.unset" {
                    state.facets.remove(&state_key);
                } else {
                    state.facets.insert(state_key, after.clone());
                }
                FacetTransitionEvidence {
                    key: key.to_string(),
                    before,
                    after,
                }
            })
        }
        _ => None,
    };
    (fields, facet)
}

fn matches_clause(
    index: usize,
    clause: &ActionClause,
    context: &MatchContext<'_>,
) -> Option<Value> {
    let MatchContext {
        event,
        payload,
        subjects,
        state,
        schema_rows,
        fields,
        facet,
        terminalities,
    } = context;
    match clause {
        ActionClause::Event {
            event_types,
            event_families,
            changed_fields_any,
            changed_fields_all,
        } => {
            let changed = changed_fields(event, payload);
            let families = classify_event_families(event, payload);
            let matched = event_types
                .as_ref()
                .is_none_or(|types| types.contains(&event.event_type))
                && event_families.as_ref().is_none_or(|wanted| {
                    wanted.iter().any(|value| families.contains(value.as_str()))
                })
                && changed_fields_any
                    .as_ref()
                    .is_none_or(|wanted| wanted.iter().any(|field| changed.contains(field)))
                && changed_fields_all
                    .as_ref()
                    .is_none_or(|wanted| wanted.iter().all(|field| changed.contains(field)));
            matched.then(|| {
                json!({
                    "clause": index,
                    "kind": "event",
                    "event_type": event.event_type,
                    "event_families": families,
                    "changed_fields": changed,
                })
            })
        }
        ActionClause::FieldTransition {
            field,
            from_value,
            to_value,
            to_terminality,
        } => {
            let (before, after) = fields.get(field)?;
            let vocab_ref = governing_field_vocabulary(schema_rows, state, &event.record_id, field);
            let before = GovernedValue {
                value: before.clone(),
                vocab_ref: vocab_ref.clone(),
            };
            let after = GovernedValue {
                value: after.clone(),
                vocab_ref: vocab_ref.clone(),
            };
            let after_terminality = terminalities.get(&after);
            let matched = from_value.matches(&before.value)
                && to_value.matches(&after.value)
                && to_terminality
                    .as_ref()
                    .is_none_or(|wanted| after_terminality == Some(wanted.as_str()));
            matched.then(|| {
                json!({
                    "clause": index,
                    "kind": "field_transition",
                    "field": field,
                    "before": before.value,
                    "after": after.value,
                    "vocab_ref": vocab_ref,
                    "before_terminality": terminalities.get(&before),
                    "after_terminality": after_terminality,
                })
            })
        }
        ActionClause::FacetTransition {
            key,
            from_value,
            to_value,
            to_terminality,
        } => {
            let facet = facet.as_ref()?;
            let after_terminality = terminalities.get(&facet.after);
            let matched = key == &facet.key
                && from_value.matches(&facet.before.value)
                && to_value.matches(&facet.after.value)
                && to_terminality
                    .as_ref()
                    .is_none_or(|wanted| after_terminality == Some(wanted.as_str()));
            matched.then(|| {
                json!({
                    "clause": index,
                    "kind": "facet_transition",
                    "key": key,
                    "before": facet.before.value,
                    "after": facet.after.value,
                    "before_vocab_ref": facet.before.vocab_ref,
                    "after_vocab_ref": facet.after.vocab_ref,
                    "before_terminality": terminalities.get(&facet.before),
                    "after_terminality": after_terminality,
                })
            })
        }
        ActionClause::LinkChange {
            change,
            relationship,
            direction,
        } => {
            let actual_change = match event.event_type.as_str() {
                "link.added" => LinkChangeKind::Added,
                "link.removed" => LinkChangeKind::Removed,
                _ => return None,
            };
            let source = payload.get("source_id").and_then(Value::as_str)?;
            let target = payload.get("target_id").and_then(Value::as_str)?;
            let actual_relationship = payload.get("relationship").and_then(Value::as_str)?;
            let out = subjects.contains(source);
            let in_ = subjects.contains(target);
            let wanted_direction = direction.unwrap_or(LinkDirection::Both);
            let direction_matches = match wanted_direction {
                LinkDirection::Out => out,
                LinkDirection::In => in_,
                LinkDirection::Both => out || in_,
            };
            let matched = change
                .as_ref()
                .is_none_or(|wanted| *wanted == actual_change)
                && relationship
                    .as_ref()
                    .is_none_or(|wanted| wanted == actual_relationship)
                && direction_matches;
            matched.then(|| {
                json!({
                    "clause": index,
                    "kind": "link_change",
                    "change": match actual_change { LinkChangeKind::Added => "added", LinkChangeKind::Removed => "removed" },
                    "relationship": actual_relationship,
                    "direction": match (out, in_) { (true, true) => "both", (true, false) => "out", (false, true) => "in", _ => "neither" },
                    "source_id": source,
                    "target_id": target,
                })
            })
        }
    }
}

/// Scan and fold one pinned prefix. `prepare_event` applies caller-relative
/// redaction before actor filters, so filtering cannot become an identity
/// oracle; action transitions continue to use the canonical payload.
pub async fn query<Fut>(
    db: &Db,
    subjects: HashSet<String>,
    args: &ActivityArgs,
    principal: Option<crate::authorization::Principal<'_>>,
    prepare_event: impl FnMut(EventRow) -> Fut,
) -> Result<ActivityPage>
where
    Fut: std::future::Future<Output = Result<(EventRow, Value)>>,
{
    query_in_pools(
        db.write_pool(),
        db.write_pool(),
        subjects,
        args,
        principal,
        prepare_event,
    )
    .await
}

pub(crate) async fn query_in_pools<Fut>(
    content_log_pool: &sqlx::SqlitePool,
    authority_pool: &sqlx::SqlitePool,
    subjects: HashSet<String>,
    args: &ActivityArgs,
    principal: Option<crate::authorization::Principal<'_>>,
    mut prepare_event: impl FnMut(EventRow) -> Fut,
) -> Result<ActivityPage>
where
    Fut: std::future::Future<Output = Result<(EventRow, Value)>>,
{
    validate(args)?;
    let after_seq = args.after_local_seq.unwrap_or(0);
    let high_water_seq = args.through_local_seq.ok_or_else(|| {
        contract_violation("query_record activity requires a pinned through_local_seq")
    })?;
    if after_seq > high_water_seq {
        return Err(contract_violation(format!(
            "query_record activity after_local_seq {after_seq} must not exceed high_water_local_seq {high_water_seq}"
        )));
    }
    let current_head: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(seq), 0) FROM content_events")
        .fetch_one(content_log_pool)
        .await?;
    if high_water_seq > current_head {
        return Err(contract_violation(
            "query_record activity through_local_seq is beyond available history",
        ));
    }
    if subjects.is_empty() {
        return Ok(ActivityPage {
            shape: "activity",
            activities: Vec::new(),
            matched_event_count: 0,
            high_water_local_seq: high_water_seq,
            subject_as_of_local_seq: high_water_seq,
            has_more: false,
        });
    }
    let terminalities = terminality_index_in_pool(authority_pool).await?;
    let schema_rows =
        crate::query::cascade::schema_config_rows_for_principal_in_pool(authority_pool, principal)
            .await?;
    let accounts = args
        .actors
        .as_ref()
        .map(|actors| actors.accounts.iter().cloned().collect::<HashSet<_>>());
    let limit = args.limit.unwrap_or(DEFAULT_ACTIVITY_LIMIT) as usize;
    let mut state = TransitionState::default();
    let mut matched = Vec::with_capacity(limit);
    let mut has_more = false;
    let mut raw_cursor = 0;
    'pages: loop {
        let raw_page = crate::query::events::change_window_in_pool(
            content_log_pool,
            raw_cursor,
            Some(high_water_seq),
            MAX_ACTIVITY_LIMIT,
        )
        .await?;
        let raw_has_more = raw_page.has_more;
        for event in raw_page.events {
            if matches!(
                event.event_type.as_str(),
                "reconciliation.recorded.v1"
                    | "unit.superseded.v1"
                    | "receipt.dependency_audited.v1"
            ) {
                continue;
            }
            let payload = parsed_payload(&event)?;
            let touches_subject = subjects.contains(&event.record_id)
                || matches!(event.event_type.as_str(), "link.added" | "link.removed")
                    && payload
                        .get("source_id")
                        .and_then(Value::as_str)
                        .zip(payload.get("target_id").and_then(Value::as_str))
                        .is_some_and(|(source, target)| {
                            subjects.contains(source) || subjects.contains(target)
                        });
            if !touches_subject {
                continue;
            }
            // Fold the complete subject prefix, including events before the page
            // cursor, so transition evidence remains event-local on every page.
            let (fields, facet) = transition_values(&mut state, &event, &payload);
            if event.local_seq <= after_seq {
                continue;
            }
            let can_view_event_record = match principal {
                Some(principal) => crate::authorization::effective_capability_in_pool(
                    authority_pool,
                    principal,
                    &event.record_id,
                )
                .await
                .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View)),
                None => true,
            };
            if !can_view_event_record {
                continue;
            }
            // Occurrence selectors belong to an independently protected
            // artefact, not merely to the Unit event stream. Suppress before
            // match evaluation and caller-visible page occupancy.
            if event.event_type == "occurrence.bound.v1" {
                let occurrence_visible = match principal {
                    Some(principal) => {
                        let artefact_id = payload
                            .get("artefact_revision")
                            .and_then(|revision| revision.get("subject_id"))
                            .and_then(Value::as_str);
                        match artefact_id {
                            Some(artefact_id) => {
                                crate::authorization::effective_capability_in_pool(
                                    authority_pool,
                                    principal,
                                    artefact_id,
                                )
                                .await
                                .is_ok_and(|capability| {
                                    capability.allows(crate::authorization::Capability::View)
                                })
                            }
                            None => false,
                        }
                    }
                    None => true,
                };
                if !occurrence_visible {
                    continue;
                }
            }
            let (visible_event, rendered_event) = prepare_event(event.clone()).await?;
            // Actor predicates run against the same redacted identity used by the
            // rendered envelope, so filtering cannot become an actor-presence oracle.
            if accounts.as_ref().is_some_and(|accounts| {
                visible_event
                    .actor
                    .as_ref()
                    .is_none_or(|actor| !accounts.contains(actor))
            }) {
                continue;
            }
            let matches = args
                .actions
                .any
                .iter()
                .enumerate()
                .filter_map(|(index, clause)| {
                    matches_clause(
                        index,
                        clause,
                        &MatchContext {
                            event: &event,
                            payload: &payload,
                            subjects: &subjects,
                            state: &state,
                            schema_rows: &schema_rows,
                            fields: &fields,
                            facet: &facet,
                            terminalities: &terminalities,
                        },
                    )
                })
                .collect::<Vec<_>>();
            if matches.is_empty() {
                continue;
            }
            if matched.len() == limit {
                has_more = true;
                break 'pages;
            }
            matched.push(ActivityItem {
                event: rendered_event,
                matches,
            });
        }
        if !raw_has_more {
            break;
        }
        raw_cursor = raw_page.scanned_through_seq;
    }
    Ok(ActivityPage {
        shape: "activity",
        matched_event_count: matched.len(),
        activities: matched,
        high_water_local_seq: high_water_seq,
        subject_as_of_local_seq: high_water_seq,
        has_more,
    })
}
