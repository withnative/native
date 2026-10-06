//! Pure, bounded field discovery for the future SQL population adapter.
//!
//! Callers must supply only global/caller-visible schema rows and a consistent
//! vocabulary snapshot. This module neither authorizes rows nor reads records.
//! An anchor describes its direct members, never the anchor itself. No public
//! SQL relation is registered here. Parsed-input limits complement (not replace)
//! the adapter's raw schema-cell preflight and SQLite progress handler.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};
use std::time::Instant;

use serde::Serialize;
use serde_json::Value;

use super::cascade::{self, SchemaConfigRow};
use crate::domain_transaction::{declared_disambiguation, declared_type_is_json_object};
use crate::meta::vocabulary::{resolve_vocab_ref, VocabularyRow, VocabularyValueRow};
use crate::schema::{SPINE_FACET_KEYS, SPINE_TYPES};
use crate::typed_time::Disambiguation;

/// Bounds include intermediate context enumeration and input rows, not only
/// final output. Byte sizes are serialized UTF-8 JSON, including escaping.
/// Input structure, context expansion, output and cache ceilings bound separate
/// regions/work. They are not an exact total-process physical heap ceiling;
/// caller-owned containers may already have excess reserved capacity.
#[derive(Debug, Clone, Copy)]
pub struct BuildLimits {
    pub input_rows: usize,
    pub input_nodes: usize,
    pub input_bytes: usize,
    pub cell_bytes: usize,
    pub emitted_rows: usize,
    pub emitted_bytes: usize,
}

impl Default for BuildLimits {
    fn default() -> Self {
        Self {
            input_rows: 50_000,
            input_nodes: 100_000,
            input_bytes: 4 * 1024 * 1024,
            cell_bytes: 256 * 1024,
            emitted_rows: 50_000,
            emitted_bytes: 4 * 1024 * 1024,
        }
    }
}

/// The SQL adapter must map these to Timeout, ResultTooLarge, or an input
/// integrity error respectively; size failures are never timeouts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    Timeout,
    ResultTooLarge(&'static str),
    InvalidInput(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct DefinitionContext {
    pub scope_id: Option<String>,
    pub r#type: String,
    pub kind: Option<String>,
}

impl DefinitionContext {
    /// Opaque, injective tuple encoding: null and empty strings differ, and
    /// JSON escaping preserves pipes, colons, Unicode and legacy scope IDs.
    pub fn context_ref(&self) -> String {
        serde_json::to_string(&(&self.scope_id, &self.r#type, &self.kind))
            .expect("string tuple serializes")
    }
}

/// Declaration metadata, not a promise that historical stored data conforms.
/// Inline refs identify lossless serialized carriers, not semantic sets:
/// object member order, numeric spelling and signed zero affect identity.
/// Both constraints remain explicit when inline values AND vocabulary apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldConstraint {
    pub declared_type: Option<String>,
    pub value_encoding: &'static str,
    pub disambiguation: Option<&'static str>,
    pub format: Option<String>,
    pub required: bool,
    pub axis_key: Option<String>,
    pub axis_label: Option<String>,
    pub governance: Option<&'static str>,
    pub options_ref: Option<String>,
    pub vocab_ref: Option<String>,
    pub vocab_missing: bool,
    pub option_count: Option<usize>,
    pub inline_options_ref: Option<String>,
    pub inline_option_count: Option<usize>,
    pub object_schema: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldDefinition {
    pub context: DefinitionContext,
    pub context_ref: String,
    pub scope_declares_shape: bool,
    pub key: String,
    pub position: usize,
    pub spine: bool,
    pub constraint: FieldConstraint,
    pub source: &'static str,
    pub shape_key: Option<String>,
    pub enforced: bool,
    /// Present only when an anchored winner overrides a workspace declaration.
    /// Includes both constraints and global time/encoding metadata; the SQL
    /// adapter may flatten this into its eventual enforced_* columns.
    pub enforced_constraint: Option<FieldConstraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldOption {
    pub options_ref: String,
    pub position: usize,
    /// Writer's stored text form. None for unwriteable historical null/bool/
    /// array inline entries; value_json still faithfully describes them.
    pub value: Option<String>,
    pub value_json: Option<String>,
    pub gloss: Option<String>,
    pub terminality: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuiltFields {
    pub definitions: Vec<FieldDefinition>,
    pub options: Vec<FieldOption>,
}

struct Budget {
    limits: BuildLimits,
    deadline: Instant,
    rows: usize,
    bytes: usize,
}

impl Budget {
    fn check(&self) -> Result<(), BuildError> {
        if Instant::now() >= self.deadline {
            Err(BuildError::Timeout)
        } else {
            Ok(())
        }
    }

    fn emit<T: Serialize>(&mut self, row: &T) -> Result<(), BuildError> {
        self.check()?;
        if self.rows >= self.limits.emitted_rows {
            return Err(BuildError::ResultTooLarge("emitted rows"));
        }
        let remaining = self.limits.emitted_bytes.saturating_sub(self.bytes);
        let bytes = json_size(row, remaining, self.deadline, "emitted bytes")?;
        self.bytes += bytes;
        self.rows += 1;
        Ok(())
    }

    fn cell<T: Serialize>(&self, value: &T) -> Result<(), BuildError> {
        json_size(value, self.limits.cell_bytes, self.deadline, "cell bytes")?;
        Ok(())
    }
}

/// Maximum values on one root-to-leaf path. This conservative ceiling is
/// compatible with ordinary serde_json parser input. It is enforced here even
/// for directly constructed Values, before recursive serialization/cloning.
pub const MAX_INPUT_VALUE_DEPTH: usize = 128;

enum Children<'a> {
    Array(std::slice::Iter<'a, Value>),
    Object(serde_json::map::Values<'a>),
}

impl<'a> Children<'a> {
    fn next(&mut self) -> Option<&'a Value> {
        match self {
            Self::Array(values) => values.next(),
            Self::Object(values) => values.next(),
        }
    }
}

/// Borrowed depth-first walk: one iterator per open container, never a vector
/// of all child references. A node is charged before pushing its frame. Stack
/// length is bounded by MAX_INPUT_VALUE_DEPTH regardless of breadth or input
/// depth, and the node count is shared across all roots, including unused data.
fn guard_parsed_inputs(
    rows: &[SchemaConfigRow],
    values: &[VocabularyValueRow],
    max_nodes: usize,
    mut check: impl FnMut() -> Result<(), BuildError>,
) -> Result<(), BuildError> {
    let mut nodes = 0usize;
    for root in rows
        .iter()
        .map(|row| &row.data)
        .chain(values.iter().map(|value| &value.metadata))
    {
        let mut stack = Vec::<Children<'_>>::new();
        let mut pending = Some(root);
        loop {
            check()?;
            if let Some(value) = pending.take() {
                if stack.len() + 1 > MAX_INPUT_VALUE_DEPTH {
                    return Err(BuildError::ResultTooLarge("input depth"));
                }
                if nodes >= max_nodes {
                    return Err(BuildError::ResultTooLarge("input nodes"));
                }
                nodes += 1;
                let children = match value {
                    Value::Array(values) => Some(Children::Array(values.iter())),
                    Value::Object(values) => Some(Children::Object(values.values())),
                    _ => None,
                };
                if let Some(mut children) = children {
                    if let Some(child) = children.next() {
                        // Current node/depth were checked before allocating a
                        // single frame; siblings stay in the borrowed iterator.
                        stack.push(children);
                        pending = Some(child);
                        continue;
                    }
                }
            }
            loop {
                check()?;
                let Some(children) = stack.last_mut() else {
                    break;
                };
                if let Some(child) = children.next() {
                    pending = Some(child);
                    break;
                }
                stack.pop();
            }
            if pending.is_none() {
                break;
            }
        }
    }
    check()?;
    Ok(())
}

/// Count without allocating a serialized copy; check the deadline during
/// serialization too, so a single large object cannot bypass the budget.
fn json_size<T: Serialize>(
    value: &T,
    limit: usize,
    deadline: Instant,
    label: &'static str,
) -> Result<usize, BuildError> {
    struct Counter {
        size: usize,
        limit: usize,
        deadline: Instant,
        label: &'static str,
        failure: Option<BuildError>,
    }
    impl Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let failure = if Instant::now() >= self.deadline {
                Some(BuildError::Timeout)
            } else if bytes.len() > self.limit.saturating_sub(self.size) {
                Some(BuildError::ResultTooLarge(self.label))
            } else {
                None
            };
            if let Some(failure) = failure {
                self.failure = Some(failure);
                return Err(io::Error::other("field builder budget exceeded"));
            }
            self.size += bytes.len();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter {
        size: 0,
        limit,
        deadline,
        label,
        failure: None,
    };
    serde_json::to_writer(&mut counter, value).map_err(|_| {
        counter
            .failure
            .clone()
            .unwrap_or(BuildError::InvalidInput("JSON input"))
    })?;
    Ok(counter.size)
}

/// Charge *all* contributing copies, including overwritten slots, before the
/// unchanged cascade can allocate. This is a conservative allocation/work
/// budget, not serialized output size: each JSON node/map entry has overhead.
/// The callback keeps expiry checks in row/facet/value loops and lets tests
/// inject expiry at a contributing facet without relying on wall-clock races.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ResolutionStep {
    Row,
    Facet,
    Value,
}

struct Expansion<F> {
    remaining: usize,
    copies: usize,
    max_copies: usize,
    check: F,
}

impl<F: FnMut(ResolutionStep) -> Result<(), BuildError>> Expansion<F> {
    fn charge(&mut self, bytes: usize) -> Result<(), BuildError> {
        if bytes > self.remaining {
            return Err(BuildError::ResultTooLarge("resolution bytes"));
        }
        self.remaining -= bytes;
        Ok(())
    }

    fn value(&mut self, value: &Value) -> Result<(), BuildError> {
        (self.check)(ResolutionStep::Value)?;
        self.charge(64)?;
        match value {
            Value::String(text) => self.charge(text.len())?,
            Value::Array(values) => {
                for value in values {
                    self.value(value)?;
                }
            }
            Value::Object(values) => {
                for (key, value) in values {
                    self.charge(128)?;
                    self.charge(key.len())?;
                    self.value(value)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn facet(&mut self, key: &str, shape: &Value) -> Result<(), BuildError> {
        self.copy()?;
        self.charge(128)?;
        self.charge(key.len())?;
        self.value(shape)
    }

    fn copy(&mut self) -> Result<(), BuildError> {
        if self.copies >= self.max_copies {
            return Err(BuildError::ResultTooLarge("resolution copies"));
        }
        self.copies += 1;
        Ok(())
    }
}

fn with_bounded_resolution<T>(
    rows: &[SchemaConfigRow],
    context: &DefinitionContext,
    shape_key: &str,
    budget: &Budget,
    check: impl FnMut(ResolutionStep) -> Result<(), BuildError>,
    materialize: impl FnOnce() -> T,
) -> Result<T, BuildError> {
    let mut expansion = Expansion {
        remaining: budget.limits.emitted_bytes,
        copies: 0,
        max_copies: budget.limits.emitted_rows,
        check,
    };
    (expansion.check)(ResolutionStep::Row)?;
    // Include the helpers' temporary kind-key strings and empty map headers.
    expansion.charge(512)?;
    if context.kind.is_some() {
        expansion.charge(shape_key.len().saturating_mul(3))?;
    }
    // Same eight slots as cascade, using borrowed keys/scopes. This preflight
    // never constructs provenance objects or clones a declaration or key.
    for anchored in [false, true] {
        let scope = if anchored {
            let Some(scope) = context.scope_id.as_deref() else {
                continue;
            };
            Some(scope)
        } else {
            None
        };
        for key in [
            Some(context.r#type.as_str()),
            context.kind.as_ref().map(|_| shape_key),
        ]
        .into_iter()
        .flatten()
        {
            for layer in ["pack", "user"] {
                for row in rows {
                    (expansion.check)(ResolutionStep::Row)?;
                    if row.layer != layer || row.applies_to_collection_id.as_deref() != scope {
                        continue;
                    }
                    let Some(facets) = row
                        .data
                        .get("shapes")
                        .and_then(|shapes| shapes.get(key))
                        .and_then(|shape| shape.get("facets"))
                        .and_then(Value::as_object)
                    else {
                        continue;
                    };
                    for (facet_key, shape) in facets {
                        (expansion.check)(ResolutionStep::Facet)?;
                        expansion.facet(facet_key, shape)?;
                        // Workspace declarations are also copied by the
                        // separately resolved writer enforcement map.
                        if !anchored {
                            expansion.facet(facet_key, shape)?;
                        }
                        expansion.copy()?;
                        expansion.charge(128)?;
                        expansion.charge(facet_key.len())?;
                        if let Some(bearer) = scope {
                            expansion.charge(64 + 4 * (128 + 64))?;
                            for text in [
                                "bearer_id",
                                "schema_row_id",
                                "layer",
                                "shape_key",
                                bearer,
                                row.id.as_str(),
                                row.layer.as_str(),
                                key,
                            ] {
                                expansion.charge(text.len())?;
                            }
                        } else {
                            expansion.charge(64)?;
                            expansion.charge(row.layer.len())?;
                            expansion.charge(1)?;
                            expansion.charge(key.len())?;
                        }
                    }
                }
            }
        }
    }
    (expansion.check)(ResolutionStep::Value)?;
    let result = materialize();
    // Helpers are uninterruptible, but their expanded work is now bounded.
    (expansion.check)(ResolutionStep::Value)?;
    Ok(result)
}

struct Builder<'a> {
    budget: Budget,
    vocabularies: &'a [VocabularyRow],
    values: &'a [VocabularyValueRow],
    // Canonical bytes verify identity before deduplication. Tagged references
    // cannot collide with an unrestricted vocabulary ID.
    inline_sets: BTreeMap<String, Vec<u8>>,
    inline_bytes: usize,
    vocabulary_sets: BTreeMap<String, usize>,
    output: BuiltFields,
}

impl Builder<'_> {
    fn inline_options(&mut self, values: &[Value]) -> Result<String, BuildError> {
        self.budget.check()?;
        // JCS is used for identity only, never to rewrite stored object text.
        // JCS alone erases numeric spellings (1 vs 1.0) which the writer's
        // inline membership/stored text may distinguish. Canonicalize their
        // lossless JSON-text carriers instead; strings retain their quotes,
        // so string "1" also remains distinct from number 1.
        // Preflight every temporary carrier/canonical byte before allocating.
        // Canonical strings can escape each carrier byte up to sixfold.
        let available = self
            .budget
            .limits
            .emitted_bytes
            .saturating_sub(self.inline_bytes);
        let mut carrier_bytes = values.len().saturating_mul(std::mem::size_of::<String>());
        let mut canonical_capacity = 2usize;
        for value in values {
            self.budget.check()?;
            let bytes = json_size(
                value,
                available,
                self.budget.deadline,
                "inline temporary bytes",
            )?;
            carrier_bytes = carrier_bytes.saturating_add(bytes);
            canonical_capacity = canonical_capacity
                .saturating_add(bytes.saturating_mul(6))
                .saturating_add(3);
            if carrier_bytes
                .saturating_add(canonical_capacity)
                .saturating_add(256)
                > available
            {
                return Err(BuildError::ResultTooLarge("inline temporary bytes"));
            }
        }
        if carrier_bytes
            .saturating_add(canonical_capacity)
            .saturating_add(256)
            > available
        {
            return Err(BuildError::ResultTooLarge("inline temporary bytes"));
        }
        let mut identity = Vec::with_capacity(values.len());
        for value in values {
            self.budget.check()?;
            let size = json_size(
                value,
                available,
                self.budget.deadline,
                "inline temporary bytes",
            )?;
            let mut carrier = Vec::with_capacity(size);
            serde_json::to_writer(&mut carrier, value).expect("value serializes");
            identity.push(String::from_utf8(carrier).expect("JSON is UTF-8"));
        }
        let mut canonical = Vec::with_capacity(canonical_capacity);
        serde_jcs::to_writer(&mut canonical, &identity)
            .map_err(|_| BuildError::InvalidInput("inline canonical JSON"))?;
        drop(identity);
        self.budget.check()?;
        use sha2::{Digest, Sha256};
        let digest = hex::encode(Sha256::digest(&canonical));
        let reference = serde_json::to_string(&["values", &digest]).expect("strings serialize");
        self.budget.cell(&reference)?;
        if let Some(existing) = self.inline_sets.get(&reference) {
            if existing != &canonical {
                return Err(BuildError::InvalidInput("inline digest collision"));
            }
            return Ok(reference);
        }
        for (index, value) in values.iter().enumerate() {
            self.budget.check()?;
            let stored = match value {
                Value::String(text) => Some(text.clone()),
                Value::Number(number) => Some(number.to_string()),
                Value::Object(_) => Some(serde_json::to_string(value).expect("value serializes")),
                _ => None,
            };
            let value_json = serde_json::to_string(value).expect("value serializes");
            self.budget.cell(&stored)?;
            self.budget.cell(&value_json)?;
            let row = FieldOption {
                options_ref: reference.clone(),
                position: index + 1,
                value: stored,
                value_json: Some(value_json),
                gloss: None,
                terminality: None,
            };
            self.budget.emit(&row)?;
            self.output.options.push(row);
        }
        self.inline_bytes = self
            .inline_bytes
            .saturating_add(canonical.capacity())
            .saturating_add(256);
        self.inline_sets.insert(reference.clone(), canonical);
        Ok(reference)
    }

    fn vocabulary_options(&mut self, id: &str) -> Result<(String, usize), BuildError> {
        self.budget.check()?;
        let reference = serde_json::to_string(&["vocabulary", id]).expect("strings serialize");
        self.budget.cell(&reference)?;
        if let Some(count) = self.vocabulary_sets.get(id) {
            return Ok((reference, *count));
        }
        let mut values = Vec::new();
        for value in self.values {
            self.budget.check()?;
            if value.vocabulary_id == id && value.status == "active" && value.alias_of.is_none() {
                values.push(value);
            }
        }
        values.sort_by(|a, b| {
            a.ordinal
                .partial_cmp(&b.ordinal)
                .expect("ordinals preflighted finite")
                .then_with(|| a.value.cmp(&b.value))
                .then_with(|| a.id.cmp(&b.id))
        });
        for (index, value) in values.iter().enumerate() {
            self.budget.check()?;
            self.budget.cell(&value.value)?;
            self.budget.cell(&value.gloss)?;
            self.budget.cell(&value.terminality)?;
            let row = FieldOption {
                options_ref: reference.clone(),
                position: index + 1,
                value: Some(value.value.clone()),
                value_json: None,
                gloss: value.gloss.clone(),
                terminality: Some(value.terminality.clone()),
            };
            self.budget.emit(&row)?;
            self.output.options.push(row);
        }
        self.vocabulary_sets.insert(id.to_owned(), values.len());
        Ok((reference, values.len()))
    }

    fn constraint(&mut self, shape: &Value) -> Result<FieldConstraint, BuildError> {
        self.budget.check()?;
        let text = |key| shape.get(key).and_then(Value::as_str).map(str::to_owned);
        let declared_type = text("type");
        let value_encoding = if declared_type_is_json_object(declared_type.as_deref()) {
            "json_object"
        } else if declared_type.as_deref() == Some("number") {
            "number"
        } else {
            "text"
        };
        let disambiguation = if matches!(declared_type.as_deref(), Some("zoned" | "when")) {
            Some(match declared_disambiguation(shape) {
                Disambiguation::Reject => "reject",
                Disambiguation::Compatible => "compatible",
            })
        } else {
            None
        };
        // Match the writer's or_else precedence, even for malformed historic
        // vocab members: a non-string vocab suppresses vocab_ref.
        let vocab_ref = shape
            .get("vocab")
            .or_else(|| shape.get("vocab_ref"))
            .and_then(Value::as_str)
            .map(str::to_owned);
        let inline = shape.get("values").and_then(Value::as_array);
        let inline_options_ref = inline
            .map(|values| self.inline_options(values))
            .transpose()?;
        let inline_option_count = inline.map(Vec::len);
        let mut options_ref = inline_options_ref.clone();
        let mut option_count = inline_option_count;
        let mut vocab_missing = false;
        if let Some(raw) = &vocab_ref {
            let designator = resolve_vocab_ref(raw);
            // Writer resolves id OR name, ordered by id, rather than id-first.
            let mut found = None::<&VocabularyRow>;
            for vocabulary in self.vocabularies {
                self.budget.check()?;
                if (vocabulary.id == designator || vocabulary.name == designator)
                    && found.is_none_or(|old| vocabulary.id < old.id)
                {
                    found = Some(vocabulary);
                }
            }
            if let Some(vocabulary) = found {
                let (reference, count) = self.vocabulary_options(&vocabulary.id)?;
                options_ref = Some(reference);
                option_count = Some(count);
            } else {
                vocab_missing = true;
                options_ref = None;
                option_count = Some(0);
            }
        }
        let governance = match (vocab_ref.is_some(), inline.is_some()) {
            (true, true) => Some("vocabulary_and_values"),
            (true, false) => Some("vocabulary"),
            (false, true) => Some("values"),
            (false, false) => None,
        };
        let axis = shape.get("axis");
        let constraint = FieldConstraint {
            declared_type,
            value_encoding,
            disambiguation,
            format: text("format"),
            required: shape
                .get("required")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            axis_key: axis
                .and_then(|axis| axis.get("key"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            axis_label: axis
                .and_then(|axis| axis.get("label"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            governance,
            options_ref,
            vocab_ref,
            vocab_missing,
            option_count,
            inline_options_ref,
            inline_option_count,
            object_schema: shape
                .get("json_schema")
                .map(|value| serde_json::to_string(value).expect("value serializes")),
        };
        self.budget.cell(&constraint.declared_type)?;
        self.budget.cell(&constraint.format)?;
        self.budget.cell(&constraint.axis_key)?;
        self.budget.cell(&constraint.axis_label)?;
        self.budget.cell(&constraint.vocab_ref)?;
        self.budget.cell(&constraint.object_schema)?;
        Ok(constraint)
    }
}

/// Build an all-or-error snapshot. Sorting does not mutate the supplied rows.
/// `deadline` is absolute, allowing population and SELECT to share one budget.
/// Vocabulary inputs need unique IDs/names and finite ordinals, as in storage.
/// All schema data and vocabulary-value metadata are structurally guarded;
/// callers need not establish a parser-depth precondition.
pub fn build_fields(
    rows: &[SchemaConfigRow],
    vocabularies: &[VocabularyRow],
    values: &[VocabularyValueRow],
    limits: BuildLimits,
    deadline: Instant,
) -> Result<BuiltFields, BuildError> {
    let mut builder = Builder {
        budget: Budget {
            limits,
            deadline,
            rows: 0,
            bytes: 0,
        },
        vocabularies,
        values,
        inline_sets: BTreeMap::new(),
        inline_bytes: 0,
        vocabulary_sets: BTreeMap::new(),
        output: BuiltFields {
            definitions: Vec::new(),
            options: Vec::new(),
        },
    };
    builder.budget.check()?;
    if rows
        .len()
        .saturating_add(vocabularies.len())
        .saturating_add(values.len())
        > limits.input_rows
    {
        return Err(BuildError::ResultTooLarge("input rows"));
    }
    // Must precede *all* recursive serialization, cloning, resolution and
    // canonicalization, including metadata on unused vocabulary values.
    guard_parsed_inputs(rows, values, limits.input_nodes, || builder.budget.check())?;
    let mut bytes = 0;
    for row in rows {
        builder.budget.cell(&row.data)?;
        builder.budget.cell(&row.applies_to_collection_id)?;
        bytes += json_size(
            row,
            limits.input_bytes.saturating_sub(bytes),
            deadline,
            "input bytes",
        )?;
        if !matches!(row.layer.as_str(), "pack" | "user") || !row.data.is_object() {
            return Err(BuildError::InvalidInput("schema row"));
        }
    }
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for vocabulary in vocabularies {
        bytes += json_size(
            vocabulary,
            limits.input_bytes.saturating_sub(bytes),
            deadline,
            "input bytes",
        )?;
        if !ids.insert(&vocabulary.id) || !names.insert(&vocabulary.name) {
            return Err(BuildError::InvalidInput("duplicate vocabulary identity"));
        }
    }
    let mut value_ids = BTreeSet::new();
    let mut value_keys = BTreeSet::new();
    for value in values {
        bytes += json_size(
            value,
            limits.input_bytes.saturating_sub(bytes),
            deadline,
            "input bytes",
        )?;
        if !value.ordinal.is_finite()
            || !value_ids.insert(&value.id)
            || !value_keys.insert((&value.vocabulary_id, &value.value))
        {
            return Err(BuildError::InvalidInput(
                "vocabulary value identity or ordinal",
            ));
        }
    }
    let mut rows = rows.to_vec();
    rows.sort_by(|a, b| {
        a.layer
            .cmp(&b.layer)
            .then_with(|| a.created_at.cmp(&b.created_at))
            .then_with(|| a.id.cmp(&b.id))
    });
    let mut row_ids = BTreeSet::new();
    if rows.iter().any(|row| !row_ids.insert(&row.id)) {
        return Err(BuildError::InvalidInput("duplicate schema row identity"));
    }
    let mut global: BTreeMap<&str, BTreeSet<String>> = SPINE_TYPES
        .into_iter()
        .map(|t| (t, BTreeSet::new()))
        .collect();
    let mut anchors: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
    let mut shape_keys = 0usize;
    for row in &rows {
        if let Some(shapes) = row.data.get("shapes").and_then(Value::as_object) {
            for (key, shape) in shapes {
                builder.budget.check()?;
                shape_keys += 1;
                if shape_keys > limits.input_rows {
                    return Err(BuildError::ResultTooLarge("shape keys"));
                }
                if !shape.is_object() {
                    continue;
                }
                let Some((record_type, kind)) = SPINE_TYPES.iter().find_map(|t| {
                    if key == t {
                        Some((*t, None))
                    } else {
                        key.strip_prefix(&format!("{t}:"))
                            .map(|kind| (*t, Some(kind)))
                    }
                }) else {
                    continue;
                }; // unknown types are not supported record contexts
                let kinds = match &row.applies_to_collection_id {
                    Some(scope) => anchors
                        .entry((scope.clone(), record_type.to_owned()))
                        .or_default(),
                    None => global.get_mut(record_type).expect("spine type"),
                };
                if let Some(kind) = kind {
                    kinds.insert(kind.to_owned());
                }
            }
        }
    }
    let mut contexts = BTreeSet::new();
    let mut context_bytes = 0usize;
    let mut add = |scope: Option<String>,
                   record_type: &str,
                   kinds: &BTreeSet<String>|
     -> Result<(), BuildError> {
        for kind in std::iter::once(None).chain(kinds.iter().map(|kind| Some(kind.clone()))) {
            builder.budget.check()?;
            if contexts.len() >= limits.emitted_rows / SPINE_FACET_KEYS.len() {
                return Err(BuildError::ResultTooLarge("definition contexts"));
            }
            let context = DefinitionContext {
                scope_id: scope.clone(),
                r#type: record_type.to_owned(),
                kind,
            };
            // Bound the cross-product before collecting it. Row limits alone
            // do not bound repeated long anchor/kind strings.
            builder.budget.cell(&context.context_ref())?;
            context_bytes += json_size(
                &context,
                limits.emitted_bytes.saturating_sub(context_bytes),
                deadline,
                "context bytes",
            )?;
            contexts.insert(context);
        }
        Ok(())
    };
    for (record_type, kinds) in &global {
        add(None, record_type, kinds)?;
    }
    for ((scope, record_type), local) in anchors {
        let kinds = global[record_type.as_str()]
            .union(&local)
            .cloned()
            .collect();
        add(Some(scope), &record_type, &kinds)?;
    }
    for context in contexts {
        builder.budget.check()?;
        let context_ref = context.context_ref();
        builder.budget.cell(&context_ref)?;
        let kind = context.kind.as_deref();
        let scope = context.scope_id.as_deref();
        let shape_key = kind.map_or_else(
            || context.r#type.clone(),
            |kind| format!("{}:{kind}", context.r#type),
        );
        let (facets, provenance, enforced) = with_bounded_resolution(
            &rows,
            &context,
            &shape_key,
            &builder.budget,
            |_| builder.budget.check(),
            || {
                (
                    cascade::facets_for_record_context(&rows, &context.r#type, kind, scope),
                    cascade::provenance_for_record_context(&rows, &context.r#type, kind, scope),
                    cascade::facets_for_record_context(&rows, &context.r#type, kind, None),
                )
            },
        )?;
        let scope_declares_shape = rows.iter().any(|row| {
            row.applies_to_collection_id.as_deref() == scope
                && row
                    .data
                    .get("shapes")
                    .and_then(|shapes| shapes.get(&shape_key))
                    .is_some_and(Value::is_object)
        });
        let mut keys: Vec<_> = SPINE_FACET_KEYS
            .iter()
            .map(|key| (*key).to_owned())
            .collect();
        let mut extra: Vec<_> = facets
            .keys()
            .filter(|key| !SPINE_FACET_KEYS.contains(&key.as_str()))
            .cloned()
            .collect();
        extra.sort();
        keys.extend(extra);
        for (index, key) in keys.into_iter().enumerate() {
            builder.budget.check()?;
            builder.budget.cell(&key)?;
            let constraint = builder.constraint(facets.get(&key).unwrap_or(&Value::Null))?;
            let (source, winner) = match provenance.get(&key) {
                Some(Value::String(source)) => {
                    let (layer, shape_key) = source
                        .split_once(':')
                        .ok_or(BuildError::InvalidInput("provenance"))?;
                    (
                        if layer == "pack" { "pack" } else { "user" },
                        Some(shape_key.to_owned()),
                    )
                }
                Some(Value::Object(source)) => (
                    "anchored",
                    source
                        .get("shape_key")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                ),
                _ => ("spine", None),
            };
            let enforced_constraint = if source == "anchored" {
                enforced
                    .get(&key)
                    .map(|shape| builder.constraint(shape))
                    .transpose()?
            } else {
                None
            };
            let row = FieldDefinition {
                context: context.clone(),
                context_ref: context_ref.clone(),
                scope_declares_shape,
                spine: SPINE_FACET_KEYS.contains(&key.as_str()),
                key,
                position: index + 1,
                constraint,
                source,
                shape_key: winner,
                enforced: source != "anchored",
                enforced_constraint,
            };
            builder.budget.emit(&row)?;
            builder.output.definitions.push(row);
        }
    }
    builder.budget.check()?;
    builder.output.options.sort_by(|a, b| {
        a.options_ref
            .cmp(&b.options_ref)
            .then_with(|| a.position.cmp(&b.position))
    });
    builder.budget.check()?;
    Ok(builder.output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::Duration;

    fn row(id: &str, layer: &str, scope: Option<&str>, data: Value) -> SchemaConfigRow {
        SchemaConfigRow {
            id: id.into(),
            layer: layer.into(),
            name: None,
            data,
            applies_to_collection_id: scope.map(str::to_owned),
            version_lineage: None,
            created_at: "2026-10-01T00:00:00Z".into(),
        }
    }
    fn build(rows: &[SchemaConfigRow]) -> BuiltFields {
        build_fields(
            rows,
            &[],
            &[],
            BuildLimits::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap()
    }
    fn field<'a>(
        output: &'a BuiltFields,
        scope: Option<&str>,
        kind: Option<&str>,
        key: &str,
    ) -> &'a FieldDefinition {
        output
            .definitions
            .iter()
            .find(|field| {
                field.context.scope_id.as_deref() == scope
                    && field.context.r#type == "WorkItem"
                    && field.context.kind.as_deref() == kind
                    && field.key == key
            })
            .unwrap()
    }
    fn value(id: &str, vocabulary_id: &str, text: &str, ordinal: f64) -> VocabularyValueRow {
        VocabularyValueRow {
            id: id.into(),
            vocabulary_id: vocabulary_id.into(),
            value: text.into(),
            gloss: Some(format!("choice {text}")),
            status: "active".into(),
            ordinal,
            terminality: "open".into(),
            metadata: json!({}),
            alias_of: None,
        }
    }

    #[test]
    fn eight_slot_precedence_exact_flags_and_global_enforcement() {
        let mut rows = Vec::new();
        for (scope, layer, key, n) in [
            (None, "pack", "WorkItem", 1),
            (None, "user", "WorkItem", 2),
            (None, "pack", "WorkItem:task", 3),
            (None, "user", "WorkItem:task", 4),
            (Some("C"), "pack", "WorkItem", 5),
            (Some("C"), "user", "WorkItem", 6),
            (Some("C"), "pack", "WorkItem:task", 7),
            (Some("C"), "user", "WorkItem:task", 8),
        ] {
            rows.push(row(&format!("row-{n}"), layer, scope,
                json!({"shapes":{key:{"facets":{"rank":{"type":"number","format":n.to_string()}}}}})));
        }
        // Check every winning slot against the unchanged cascade itself.
        for end in 1..=8 {
            let output = build(&rows[..end]);
            let expected = cascade::facets_for_record_context(
                &rows[..end],
                "WorkItem",
                Some("task"),
                Some("C"),
            );
            let scope = if end > 4 { Some("C") } else { None };
            let kind = if end >= 3 { Some("task") } else { None };
            let actual = field(&output, scope, kind, "rank");
            assert_eq!(
                actual.constraint.format.as_deref(),
                expected["rank"]["format"].as_str()
            );
            assert_eq!(actual.enforced, end <= 4);
            if end > 4 {
                assert_eq!(
                    actual
                        .enforced_constraint
                        .as_ref()
                        .unwrap()
                        .format
                        .as_deref(),
                    Some("4")
                );
            }
        }
        let output = build(&rows);
        assert_eq!(
            field(&output, Some("C"), Some("task"), "rank").source,
            "anchored"
        );
        assert_eq!(
            field(&output, Some("C"), Some("task"), "rank")
                .shape_key
                .as_deref(),
            Some("WorkItem:task")
        );
        assert!(field(&output, Some("C"), Some("task"), "rank").scope_declares_shape);
        rows.retain(|row| row.id != "row-7" && row.id != "row-8");
        let output = build(&rows);
        // Base applies, but this scope did not declare the exact kind shape.
        assert!(cascade::scope_supplies_shape(
            &rows,
            "WorkItem",
            Some("task"),
            "C"
        ));
        assert!(!field(&output, Some("C"), Some("task"), "rank").scope_declares_shape);
        assert_eq!(
            field(&output, Some("C"), Some("task"), "rank")
                .constraint
                .format
                .as_deref(),
            Some("6")
        );
    }

    #[test]
    fn references_empty_shapes_and_order_are_lossless_and_deterministic() {
        let mut rows = vec![
            row(
                "b",
                "user",
                Some("C|WorkItem|🦀"),
                json!({"shapes":{"WorkItem":{},"WorkItem:task":{"facets":{"z":{},"a":{}}}}}),
            ),
            row(
                "a",
                "pack",
                None,
                json!({"shapes":{"WorkItem:":{},"WorkItem:task|x:🦀":{}}}),
            ),
        ];
        let output = build(&rows);
        let base = field(&output, None, None, "owner");
        let empty = field(&output, None, Some(""), "owner");
        assert_ne!(base.context_ref, empty.context_ref);
        assert_eq!(
            serde_json::from_str::<Value>(&base.context_ref).unwrap(),
            json!([null, "WorkItem", null])
        );
        assert_eq!(
            serde_json::from_str::<Value>(&empty.context_ref).unwrap(),
            json!([null, "WorkItem", ""])
        );
        assert!(empty.scope_declares_shape);
        let scope = Some("C|WorkItem|🦀");
        let fields: Vec<_> = output
            .definitions
            .iter()
            .filter(|field| {
                field.context.scope_id.as_deref() == scope
                    && field.context.kind.as_deref() == Some("task")
            })
            .map(|field| (field.key.as_str(), field.position))
            .collect();
        assert_eq!(
            fields,
            vec![
                ("lifecycle", 1),
                ("owner", 2),
                ("persistence", 3),
                ("maturity", 4),
                ("a", 5),
                ("z", 6)
            ]
        );
        assert_eq!(
            field(&output, scope, Some("task|x:🦀"), "owner").source,
            "spine"
        );
        rows.reverse();
        assert_eq!(output, build(&rows));
        // A separate anchor contributes only its own contexts, not C's fields.
        rows.push(row(
            "c",
            "user",
            Some("D"),
            json!({"shapes":{"WorkItem":{"facets":{"secret":{}}}}}),
        ));
        let output = build(&rows);
        assert!(!output
            .definitions
            .iter()
            .any(|f| f.context.scope_id.as_deref() == scope && f.key == "secret"));
    }

    #[test]
    fn time_types_use_writer_metadata_and_keep_advisory_constraint_separate() {
        let rows = vec![
            row(
                "global",
                "user",
                None,
                json!({"shapes":{"WorkItem":{"facets":{
                    "date":{"type":"date"},"instant":{"type":"instant"},
                    "zoned":{"type":"zoned","disambiguation":"reject"},"when":{"type":"when"},
                    "object":{"type":"object","json_schema":{"type":"object"}},"unknown":{"type":"historical"}
                }}}}),
            ),
            row(
                "anchor",
                "user",
                Some("C"),
                json!({"shapes":{"WorkItem":{"facets":{
                    "date":{"type":"zoned","required":true},"local":{"type":"number"}
                }}}}),
            ),
        ];
        let output = build(&rows);
        for (key, encoding, disambiguation) in [
            ("date", "text", None),
            ("instant", "text", None),
            ("zoned", "json_object", Some("reject")),
            ("when", "json_object", Some("compatible")),
            ("object", "json_object", None),
            ("unknown", "text", None),
        ] {
            let actual = field(&output, None, None, key);
            assert_eq!(actual.constraint.value_encoding, encoding);
            assert_eq!(actual.constraint.disambiguation, disambiguation);
        }
        assert_eq!(
            field(&output, None, None, "unknown")
                .constraint
                .declared_type
                .as_deref(),
            Some("historical")
        );
        let actual = field(&output, Some("C"), None, "date");
        assert!(!actual.enforced);
        assert!(actual.constraint.required);
        assert_eq!(actual.constraint.value_encoding, "json_object");
        assert_eq!(
            actual
                .enforced_constraint
                .as_ref()
                .unwrap()
                .declared_type
                .as_deref(),
            Some("date")
        );
        assert!(field(&output, Some("C"), None, "local")
            .enforced_constraint
            .is_none());
        assert_eq!(
            field(&output, None, None, "object")
                .constraint
                .object_schema
                .as_deref(),
            Some("{\"type\":\"object\"}")
        );
    }

    #[test]
    fn inline_identity_preserves_writer_types_spelling_duplicates_and_invalid_history() {
        let rows = [row(
            "a",
            "user",
            None,
            json!({"shapes":{"WorkItem":{"facets":{
                "mixed":{"values":["1",1,1.0,{"x":1},true,null,[],"1"]},
                "same":{"values":["1",1,1.0,{"x":1},true,null,[],"1"]},
                "integer":{"values":[1]},"float":{"values":[1.0]},"empty":{"values":[]},"open":{}
            }}}}),
        )];
        let output = build(&rows);
        let mixed = &field(&output, None, None, "mixed").constraint;
        assert_eq!(
            mixed.options_ref,
            field(&output, None, None, "same").constraint.options_ref
        );
        assert_eq!(mixed.inline_option_count, Some(8));
        let options: Vec<_> = output
            .options
            .iter()
            .filter(|o| Some(&o.options_ref) == mixed.options_ref.as_ref())
            .collect();
        assert_eq!(options.len(), 8);
        assert_eq!(options[0].value_json.as_deref(), Some("\"1\""));
        assert_eq!(options[1].value_json.as_deref(), Some("1"));
        assert_eq!(options[2].value_json.as_deref(), Some("1.0"));
        assert_eq!(options[0].value, options[1].value);
        assert_eq!(options[2].value.as_deref(), Some("1.0"));
        assert_eq!(options[3].value.as_deref(), Some("{\"x\":1}"));
        assert!(options[4..7]
            .iter()
            .all(|o| o.value.is_none() && o.value_json.is_some()));
        assert_eq!(options[7].position, 8);
        assert_ne!(
            field(&output, None, None, "integer").constraint.options_ref,
            field(&output, None, None, "float").constraint.options_ref
        );
        assert_eq!(
            field(&output, None, None, "empty").constraint.option_count,
            Some(0)
        );
        assert_eq!(
            field(&output, None, None, "open").constraint.governance,
            None
        );
    }

    #[test]
    fn both_constraints_missing_vocabulary_aliases_and_id_name_resolution() {
        let rows = [row(
            "a",
            "user",
            None,
            json!({"shapes":{"WorkItem":{"facets":{
                "stage":{"vocab_ref":"rec:status","values":["ready"]},"missing":{"vocab":"missing","values":[]},
                "axis":{"vocab":"status","axis":{"key":"workflow","label":"Workflow"}},
                "precedence":{"vocab":false,"vocab_ref":"status"}
            }}}}),
        )];
        let vocabularies = [
            VocabularyRow {
                id: "z".into(),
                name: "status".into(),
            },
            VocabularyRow {
                id: "status".into(),
                name: "other".into(),
            },
        ];
        // Writer's lexicographic ID tie-break picks status, not z.
        let mut values = vec![
            value("b", "status", "ready", -0.0),
            value("a", "status", "done", 0.0),
            value("c", "status", "alias", 0.0),
            value("d", "status", "old", 0.0),
            value("e", "z", "wrong", 0.0),
        ];
        values[1].terminality = "terminal_positive".into();
        values[2].alias_of = Some("a".into());
        values[3].status = "deprecated".into();
        let output = build_fields(
            &rows,
            &vocabularies,
            &values,
            BuildLimits::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        let stage = &field(&output, None, None, "stage").constraint;
        assert_eq!(stage.governance, Some("vocabulary_and_values"));
        assert_eq!(stage.option_count, Some(2));
        assert_eq!(stage.inline_option_count, Some(1));
        assert_ne!(stage.options_ref, stage.inline_options_ref);
        assert_eq!(stage.vocab_ref.as_deref(), Some("rec:status"));
        let options: Vec<_> = output
            .options
            .iter()
            .filter(|o| Some(&o.options_ref) == stage.options_ref.as_ref())
            .collect();
        assert_eq!(
            options
                .iter()
                .map(|o| o.value.as_deref().unwrap())
                .collect::<Vec<_>>(),
            vec!["done", "ready"]
        );
        assert_eq!(options[0].terminality.as_deref(), Some("terminal_positive"));
        assert_eq!(options[0].value_json, None);
        assert!(
            field(&output, None, None, "missing")
                .constraint
                .vocab_missing
        );
        assert_eq!(
            field(&output, None, None, "missing")
                .constraint
                .option_count,
            Some(0)
        );
        assert!(field(&output, None, None, "missing")
            .constraint
            .options_ref
            .is_none());
        assert_eq!(
            field(&output, None, None, "axis")
                .constraint
                .axis_key
                .as_deref(),
            Some("workflow")
        );
        assert_eq!(
            field(&output, None, None, "precedence")
                .constraint
                .governance,
            None
        );
        values.reverse();
        assert_eq!(
            output,
            build_fields(
                &rows,
                &vocabularies,
                &values,
                BuildLimits::default(),
                Instant::now() + Duration::from_secs(10)
            )
            .unwrap()
        );
        let inline = stage.inline_options_ref.as_ref().unwrap();
        let collision_vocab = [VocabularyRow {
            id: inline.clone(),
            name: "custom".into(),
        }];
        let collision_rows = [row(
            "c",
            "user",
            None,
            json!({"shapes":{"WorkItem":{"facets":{
                "v":{"vocab":inline},"i":{"values":["ready"]}
            }}}}),
        )];
        let output = build_fields(
            &collision_rows,
            &collision_vocab,
            &[],
            BuildLimits::default(),
            Instant::now() + Duration::from_secs(10),
        )
        .unwrap();
        assert_ne!(
            field(&output, None, None, "v").constraint.options_ref,
            field(&output, None, None, "i").constraint.options_ref
        );
    }

    #[test]
    fn row_input_cell_and_emitted_byte_bounds_are_all_or_error() {
        let rows = [row(
            "a",
            "user",
            None,
            json!({"shapes":{"WorkItem":{"facets":{"x":{"values":["one","two"]}}}}}),
        )];
        let deadline = Instant::now() + Duration::from_secs(10);
        let output = build(&rows);
        let emitted_rows = output.definitions.len() + output.options.len();
        let emitted_bytes: usize = output
            .definitions
            .iter()
            .map(|r| json_size(r, usize::MAX, deadline, "test").unwrap())
            .sum::<usize>()
            + output
                .options
                .iter()
                .map(|r| json_size(r, usize::MAX, deadline, "test").unwrap())
                .sum::<usize>();
        let input_bytes = json_size(&rows[0], usize::MAX, deadline, "test").unwrap();
        let limits = BuildLimits {
            input_rows: 1,
            input_bytes,
            emitted_rows,
            emitted_bytes,
            ..BuildLimits::default()
        };
        assert_eq!(
            output,
            build_fields(&rows, &[], &[], limits, deadline).unwrap()
        );
        for (limits, label) in [
            (
                BuildLimits {
                    input_rows: 0,
                    ..limits
                },
                "input rows",
            ),
            (
                BuildLimits {
                    input_bytes: input_bytes - 1,
                    ..limits
                },
                "input bytes",
            ),
            (
                BuildLimits {
                    emitted_rows: emitted_rows - 1,
                    ..limits
                },
                "emitted rows",
            ),
            (
                BuildLimits {
                    emitted_bytes: emitted_bytes - 1,
                    ..limits
                },
                "emitted bytes",
            ),
            (
                BuildLimits {
                    cell_bytes: 1,
                    ..limits
                },
                "cell bytes",
            ),
        ] {
            assert_eq!(
                build_fields(&rows, &[], &[], limits, deadline),
                Err(BuildError::ResultTooLarge(label))
            );
        }
        let mut temporary = Builder {
            budget: Budget {
                limits: BuildLimits {
                    emitted_bytes: 500,
                    ..BuildLimits::default()
                },
                deadline,
                rows: 0,
                bytes: 0,
            },
            vocabularies: &[],
            values: &[],
            inline_sets: BTreeMap::new(),
            inline_bytes: 0,
            vocabulary_sets: BTreeMap::new(),
            output: BuiltFields {
                definitions: vec![],
                options: vec![],
            },
        };
        let entries = [json!("x".repeat(100))];
        assert!(json_size(
            &entries,
            temporary.budget.limits.cell_bytes,
            deadline,
            "test"
        )
        .is_ok());
        assert_eq!(
            temporary.inline_options(&entries),
            Err(BuildError::ResultTooLarge("inline temporary bytes"))
        );
        assert!(temporary.inline_sets.is_empty() && temporary.output.options.is_empty());

        // Context cross-product is bounded before resolution/allocation.
        assert_eq!(
            build_fields(
                &[],
                &[],
                &[],
                BuildLimits {
                    emitted_rows: 39,
                    ..BuildLimits::default()
                },
                deadline
            ),
            Err(BuildError::ResultTooLarge("definition contexts"))
        );
        assert_eq!(
            build_fields(&rows, &[], &[], BuildLimits::default(), Instant::now()),
            Err(BuildError::Timeout)
        );
        // A failed invocation cannot contaminate a later independent build.
        assert_eq!(build(&rows), output);
    }

    #[test]
    fn context_cross_product_has_an_early_byte_bound() {
        let facets: serde_json::Map<_, _> =
            (0..2000).map(|n| (format!("k{n}"), json!({}))).collect();
        let large_id = "i".repeat(3 * 1024 * 1024);
        let rows = [row(
            &large_id,
            "user",
            Some("C"),
            json!({"shapes":{"WorkItem":{"facets":facets.clone()}}}),
        )];
        assert_early_resolution_rejection(
            &rows,
            DefinitionContext {
                scope_id: Some("C".into()),
                r#type: "WorkItem".into(),
                kind: None,
            },
        );
        // An ordinary UUID does not fix repeated long shape-key allocation.
        let kind = "k".repeat(2048);
        let key = format!("WorkItem:{kind}");
        let rows = [row(
            "00000000-0000-4000-8000-000000000000",
            "user",
            Some("C"),
            json!({"shapes":{key:{"facets":facets}}}),
        )];
        assert_early_resolution_rejection(
            &rows,
            DefinitionContext {
                scope_id: Some("C".into()),
                r#type: "WorkItem".into(),
                kind: Some(kind),
            },
        );

        let scope = "C".repeat(10_000);
        let mut shapes = serde_json::Map::new();
        for index in 0..20 {
            shapes.insert(format!("WorkItem:k{index}"), json!({}));
        }
        let rows = [row("long", "user", Some(&scope), json!({"shapes": shapes}))];
        // Input is small, but repeating its anchor across 21 contexts grows
        // beyond this budget before any field output can be exposed.
        assert_eq!(
            build_fields(
                &rows,
                &[],
                &[],
                BuildLimits {
                    emitted_bytes: 30_000,
                    ..BuildLimits::default()
                },
                Instant::now() + Duration::from_secs(10)
            ),
            Err(BuildError::ResultTooLarge("context bytes"))
        );
    }

    // Invoked by the existing context-bound test; checks nonmaterialization
    // through the same wrapper that production uses around cascade helpers.
    fn assert_early_resolution_rejection(rows: &[SchemaConfigRow], context: DefinitionContext) {
        let limits = BuildLimits::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(json_size(&rows[0], limits.input_bytes, deadline, "test").is_ok());
        assert!(json_size(&rows[0].data, limits.cell_bytes, deadline, "test").is_ok());
        let shape_key = context.kind.as_ref().map_or_else(
            || context.r#type.clone(),
            |kind| format!("{}:{kind}", context.r#type),
        );
        let budget = Budget {
            limits,
            deadline,
            rows: 0,
            bytes: 0,
        };
        let materialized = std::cell::Cell::new(false);
        assert_eq!(
            with_bounded_resolution(
                rows,
                &context,
                &shape_key,
                &budget,
                |_| budget.check(),
                || {
                    materialized.set(true);
                }
            ),
            Err(BuildError::ResultTooLarge("resolution bytes"))
        );
        assert!(!materialized.get());
        assert_eq!(
            build_fields(rows, &[], &[], limits, deadline),
            Err(BuildError::ResultTooLarge("resolution bytes"))
        );
    }

    #[test]
    fn deadline_checked_during_serialization_and_bad_snapshot_refused() {
        struct Slow;
        impl Serialize for Slow {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                std::thread::sleep(Duration::from_millis(10));
                serializer.serialize_str("after deadline")
            }
        }
        assert_eq!(
            json_size(
                &Slow,
                100,
                Instant::now() + Duration::from_millis(2),
                "test"
            ),
            Err(BuildError::Timeout)
        );
        // Expiry occurs at the fifth contributing facet, not serialization.
        let facets: serde_json::Map<_, _> = (0..20).map(|n| (format!("k{n}"), json!({}))).collect();
        let resolution_rows = [row(
            "ordinary",
            "user",
            Some("C"),
            json!({"shapes":{"WorkItem":{"facets":facets}}}),
        )];
        let context = DefinitionContext {
            scope_id: Some("C".into()),
            r#type: "WorkItem".into(),
            kind: None,
        };
        let budget = Budget {
            limits: BuildLimits::default(),
            deadline: Instant::now() + Duration::from_secs(10),
            rows: 0,
            bytes: 0,
        };
        let facets_seen = std::cell::Cell::new(0);
        let materialized = std::cell::Cell::new(false);
        assert_eq!(
            with_bounded_resolution(
                &resolution_rows,
                &context,
                "WorkItem",
                &budget,
                |step| {
                    if step == ResolutionStep::Facet {
                        facets_seen.set(facets_seen.get() + 1);
                        if facets_seen.get() == 5 {
                            return Err(BuildError::Timeout);
                        }
                    }
                    Ok(())
                },
                || {
                    materialized.set(true);
                }
            ),
            Err(BuildError::Timeout)
        );
        assert_eq!(facets_seen.get(), 5);
        assert!(!materialized.get());

        // Safely constructed/dropped one-over-limit fixture, not the
        // review's 100,000-deep destructor-hazard witness.
        let mut nested = Value::Null;
        for _ in 0..MAX_INPUT_VALUE_DEPTH - 1 {
            nested = Value::Array(vec![nested]);
        }
        let rows = [row("deep", "user", None, json!({"unused":nested.clone()}))];
        let limits = BuildLimits::default();
        let deadline = Instant::now() + Duration::from_secs(10);
        assert!(json_size(&rows[0], limits.input_bytes, deadline, "test").is_ok());
        assert!(json_size(&rows[0].data, limits.cell_bytes, deadline, "test").is_ok());
        assert_eq!(
            build_fields(&rows, &[], &[], limits, deadline),
            Err(BuildError::ResultTooLarge("input depth"))
        );
        // Guard is ordered before serialization byte caps even for unused
        // fields; this must remain a depth failure with a zero byte budget.
        assert_eq!(
            build_fields(
                &rows,
                &[],
                &[],
                BuildLimits {
                    input_bytes: 0,
                    ..limits
                },
                deadline
            ),
            Err(BuildError::ResultTooLarge("input depth"))
        );
        let mut unused = value("unused", "unreferenced", "unused", 0.0);
        unused.metadata = json!({"unused": nested});
        assert_eq!(
            build_fields(&[], &[], &[unused], limits, deadline),
            Err(BuildError::ResultTooLarge("input depth"))
        );

        let broad = [row(
            "broad",
            "user",
            None,
            json!({"unused":vec![Value::Null;1000]}),
        )];
        assert_eq!(
            build_fields(
                &broad,
                &[],
                &[],
                BuildLimits {
                    input_nodes: 3,
                    ..limits
                },
                deadline
            ),
            Err(BuildError::ResultTooLarge("input nodes"))
        );
        // Check expiry within the actual iterative guard, not serialization.
        let walked = std::cell::Cell::new(0);
        assert_eq!(
            guard_parsed_inputs(&broad, &[], limits.input_nodes, || {
                walked.set(walked.get() + 1);
                if walked.get() == 5 {
                    Err(BuildError::Timeout)
                } else {
                    Ok(())
                }
            }),
            Err(BuildError::Timeout)
        );
        assert_eq!(walked.get(), 5);
        // A scalar at the exact documented path-depth ceiling is admitted.
        let mut at_limit = Value::Null;
        for _ in 0..MAX_INPUT_VALUE_DEPTH - 2 {
            at_limit = Value::Array(vec![at_limit]);
        }
        let rows = [row("limit", "user", None, json!({"unused":at_limit}))];
        assert_eq!(
            build_fields(&rows, &[], &[], limits, deadline)
                .unwrap()
                .definitions
                .len(),
            SPINE_TYPES.len() * SPINE_FACET_KEYS.len()
        );

        let mut rows = vec![row("duplicate", "user", None, json!({})); 2];
        assert_eq!(
            build_fields(
                &rows,
                &[],
                &[],
                BuildLimits::default(),
                Instant::now() + Duration::from_secs(10)
            ),
            Err(BuildError::InvalidInput("duplicate schema row identity"))
        );
        rows.truncate(1);
        rows[0].layer = "unknown".into();
        assert_eq!(
            build_fields(
                &rows,
                &[],
                &[],
                BuildLimits::default(),
                Instant::now() + Duration::from_secs(10)
            ),
            Err(BuildError::InvalidInput("schema row"))
        );
    }
}
