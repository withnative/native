//! `native.mdx.v2` reusable modules: static source contracts and the verified
//! in-memory graph execution seam. Database publication/resolution stays in the
//! artifact host; this module deliberately accepts only already-resolved bytes.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use swc_common::{sync::Lrc, FileName, SourceMap};
use swc_ecma_ast::{
    Callee, Decl, ExportSpecifier, Expr, ImportSpecifier, Lit, ModuleDecl, ModuleExportName,
    ModuleItem, Pat, Prop, PropName, PropOrSpread, UnaryOp,
};
use swc_ecma_parser::{lexer::Lexer, EsSyntax, Parser, StringInput, Syntax};
use swc_ecma_visit::{Visit, VisitWith};
use uuid::Uuid;

use super::mdx::elapsed_micros;
use super::{css, mdx};

pub const RUNTIME_ID: &str = "native.mdx.v2";
pub const MODULE_SCHEMA: &str = "native.mdx.module.v1";
pub const ARTIFACT_SCHEMA: &str = "native.mdx.artifact.v2";
pub const RELEASE_SCHEMA: &str = "native.module-release.v1";
pub const NAMED_INPUT_ABI: &str = "native.named-artifact-input.v1";
/// The export that carries an artifact's author stylesheet.
pub const STYLES_EXPORT: &str = "nativeStyles";
pub const COLLECTION_ENVELOPE: &str = "native.collection-envelope.v1";
pub const GROUPED_COUNT_ENVELOPE: &str = "native.grouped-count-envelope.v1";
pub const RELATION_ENVELOPE: &str = "native.relation-envelope.v1";
pub const ARTIFACT_RECORD_SCHEMA: &str = "native.artifact-record.v1";
/// This adapter's behaviour revision, and a field in both cache keys.
///
/// Moved 3 to 4 by tier two of author CSS. Moved 4 to 5 when the accepted
/// component policy gained `BarChart` and the typed grouped-count input became
/// part of manifest admission. Moved 5 to 6 when grouped counts gained the
/// closed facet axis. Moved 6 to 7 when `PlacementPreview` joined the v2-only
/// component policy. Moved 7 to 8 when Collection-backed record relations
/// joined the named-input contract. Moved 8 to 9 when relation sources gained
/// opaque governed-SQL observation revisions. Moved 9 to 10 when governed-SQL
/// inputs gained their content-safe per-port execution receipt. Moved 10 to 11
/// when relation ports gained optional exact semantic dependency pins. Moved
/// 11 to 12 when `record.create` and its closed `RecordCreate` control joined
/// the declaration language. A bump
/// invalidates every compiled-graph key and every parsed-source key; the cold
/// pass is intentional because a cached artifact must never claim an older
/// declaration language or component policy.
pub const ADAPTER_REVISION: u64 = 12;
pub const CACHE_NAMESPACE: &str = "native.artifact-compiled-cache";

/// The element an author stylesheet is scoped to.
///
/// `.safe-tree` is the section the workbench renders the artifact's own tree
/// into. Its parent, `.safe-tree-frame`, is host-owned and deliberately NOT
/// the root: if the frame were in scope, a rule such as
/// `:scope { position: fixed; inset: 0 }` would lift the artifact out of the
/// box the host put it in, and the host could not win that back because the
/// author sheet loads later at the same origin.
pub const STYLE_SCOPE_ROOT: &str = ".safe-tree";
/// Where the author's scope ends.
///
/// `.native-interactive` marks host-owned closed controls plus authenticated
/// chart presentation whose accessible structure belongs to the host.
/// Placement does not use persistent visible host chrome: its target buttons
/// are transient and visually hidden. `@scope (root) to (limit)` excludes
/// the limit element *itself*, not merely its descendants, so an author rule
/// cannot match a marked element at all. That is the one property tier two
/// rests on, and it is a property about **matching**: author CSS cannot
/// restyle marked controls, cannot relabel them through `content`, and cannot be
/// inherited into them. `!important` changes nothing, because the rules never
/// enter the cascade in the first place.
///
/// The marker is deliberately on the closed control and **not** on an authored
/// content container. A `DropTarget` keeps the author's own content inside its
/// `<section>`; marking that section would put the author's cards outside their
/// stylesheet. The narrowing is the point: controls the host wholly owns stay
/// out of the author's reach, while authored placement presentation remains
/// visually sovereign under decision `e3fb337b`.
///
/// This replaces tier one's `.safe-tree-host`, the wrapper around one rendered
/// artifact. No `.safe-tree-host` ever occurs inside `.safe-tree`, so that
/// limit is an ancestor of the scope root and never matched anything; it
/// shipped so the delivered shape would not change when tier two arrived.
/// Nothing is lost by dropping it, because artifacts cannot nest today either,
/// and a nested host wrapper is chrome and can carry `.native-interactive`.
pub const STYLE_SCOPE_LIMIT: &str = ".native-interactive";

pub const MAX_MODULES: usize = 128;
pub const MAX_DEPTH: usize = 32;
pub const MAX_EDGES: usize = 512;
pub const MAX_EXPORTS: usize = 1024;
pub const MAX_AGGREGATE_SOURCE: usize = 4 * 1024 * 1024;
pub const MAX_AGGREGATE_COMPILED: usize = 16 * 1024 * 1024;
pub const MAX_GROUPED_COUNT_RECORDS: usize = 10_000;
pub const MAX_GROUPED_COUNT_BUCKETS: usize = 128;
pub const MAX_GROUPED_COUNT_KEY_BYTES: usize = 256;
pub const MAX_INPUT_RECORDS: usize = 10_000;
pub const MAX_INPUT_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_CACHE_ENTRIES: usize = 128;
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone)]
struct ParsedCacheEntry {
    parsed: ParsedSource,
    compiled_sha256: String,
    bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct ParsedCache {
    entries: HashMap<String, ParsedCacheEntry>,
    bytes: usize,
    clock: u64,
}

fn parsed_cache() -> &'static Mutex<ParsedCache> {
    static CACHE: OnceLock<Mutex<ParsedCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(ParsedCache::default()))
}

#[derive(Clone)]
struct CompiledGraphEntry {
    root: String,
    root_sha256: String,
    modules: HashMap<String, String>,
    module_sha256: BTreeMap<String, String>,
    bytes: usize,
    last_used: u64,
}

#[derive(Default)]
struct CompiledGraphCache {
    entries: HashMap<String, CompiledGraphEntry>,
    bytes: usize,
    clock: u64,
}

fn compiled_graph_cache() -> &'static Mutex<CompiledGraphCache> {
    static CACHE: OnceLock<Mutex<CompiledGraphCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(CompiledGraphCache::default()))
}

pub enum GraphCacheLookup {
    Hit {
        root: String,
        modules: HashMap<String, String>,
    },
    Miss,
    Corrupt,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InputDecl {
    pub envelope: String,
    pub required: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub expose_to_root: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<InputProjection>,
    /// Required for governed-SQL relation ports and forbidden for legacy
    /// Collection-backed record relations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_sha256: Option<String>,
    /// Optional exact governed-SQL dependency contract. Omission preserves
    /// manifests authored before semantic relation pins were available.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub relations: BTreeMap<String, SemanticRelationDependency>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticRelationDependency {
    pub identity: String,
    #[serde(deserialize_with = "deserialize_semantic_version")]
    pub semantic_version: u32,
}

fn deserialize_semantic_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let version = value.as_u64().or_else(|| {
        value.as_f64().and_then(|value| {
            (value.is_finite() && value.fract() == 0.0 && value >= 0.0).then_some(value as u64)
        })
    });
    version
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| serde::de::Error::custom("semantic_version must be an unsigned u32"))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InputProjection {
    GroupedCount { axis: GroupedCountAxis },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GroupedCountAxis {
    RecordField { field: GroupedCountRecordField },
    Facet { key: String },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GroupedCountRecordField {
    Kind,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRequest {
    pub capability: String,
    pub scope: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModuleInputMap {
    pub publication_event_id: String,
    pub export: String,
    pub ports: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExportInterface {
    pub kind: String,
    #[serde(default)]
    pub props: BTreeMap<String, Value>,
    #[serde(default)]
    pub args: Vec<Value>,
    #[serde(default)]
    pub result: Option<Value>,
    #[serde(default)]
    pub uses_inputs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ModuleManifest {
    pub schema: String,
    pub inputs: BTreeMap<String, InputDecl>,
    pub exports: BTreeMap<String, ExportInterface>,
    pub module_inputs: BTreeMap<String, ModuleInputMap>,
    pub capability_requests: Vec<CapabilityRequest>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema: String,
    pub inputs: BTreeMap<String, InputDecl>,
    pub module_inputs: BTreeMap<String, ModuleInputMap>,
    pub capability_requests: Vec<CapabilityRequest>,
    /// Interaction entries an artifact may invoke against the host.
    ///
    /// DECLARED, never derived: the rendered safe tree is a function of body
    /// AND input, so it cannot yield a static manifest. Serialization skips an
    /// empty set so that an artifact which declares no interactions keeps
    /// exactly the `manifest_sha256` — and therefore the compiled cache key —
    /// it had before this field existed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interactions: Vec<InteractionEntry>,
}

impl ArtifactManifest {
    pub fn interaction(&self, entry_id: &str) -> Option<&InteractionEntry> {
        self.interactions.iter().find(|entry| entry.id == entry_id)
    }
}

/// One declared, invocable interaction: a labelled effect over named operands,
/// each operand constrained to a declared domain.
///
/// The artifact declares the entry and fills its slots. It never states its own
/// scope: the host derives that from the binding, so a record operand is
/// admissible only if it resolves inside the artifact's bound input.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct InteractionEntry {
    /// Stable within one body digest — an invocation names this against the
    /// digest it rendered from, so ids need no wider uniqueness.
    pub id: String,
    pub label: String,
    pub effect: InteractionEffect,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub slots: BTreeMap<String, SlotDecl>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub facet: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<ValueSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create: Option<RecordCreateDecl>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub enum InteractionEffect {
    #[serde(rename = "facet.set")]
    FacetSet,
    #[serde(rename = "facet.unset")]
    FacetUnset,
    #[serde(rename = "record.create")]
    RecordCreate,
}

impl InteractionEffect {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FacetSet => "facet.set",
            Self::FacetUnset => "facet.unset",
            Self::RecordCreate => "record.create",
        }
    }
}

/// The manifest-authored part of a governed record creation. The host resolves
/// the destination and references, intersects the shape with current schema
/// and policy, and derives actor, authorization and attribution itself.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordCreateDecl {
    pub destination: RecordCreateDestination,
    pub shape: RecordCreateShape,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordCreateDestination {
    /// A host-approved destination fixed in the manifest.
    Literal { record_id: String },
    /// The root Collection supplied through this named artifact input.
    BoundInput { port: String },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordCreateShape {
    #[serde(rename = "type")]
    pub record_type: RecordCreateValue,
    pub kind: RecordCreateValue,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, RecordCreateValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub facets: BTreeMap<String, RecordCreateValue>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RecordCreateValue {
    /// Host-owned controls use this semantic label for person-supplied input.
    /// Literals omit it because they produce no control.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub source: RecordCreateValueSource,
    pub domain: RecordCreateValueDomain,
}

/// Where a created value comes from. `input` values travel in invocation
/// `values`; `bound_input` selections travel in invocation `slots`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordCreateValueSource {
    Literal { value: Value },
    Input { input: String },
    BoundInput { slot: String },
}

impl RecordCreateValueSource {
    /// The invocation map key this source consumes, if any. `Input` consumes
    /// `ArtifactInvocation.values`; `BoundInput` consumes its `slots` map.
    pub fn invocation_name(&self) -> Option<&str> {
        match self {
            Self::Literal { .. } => None,
            Self::Input { input } => Some(input),
            Self::BoundInput { slot } => Some(slot),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecordCreateValueDomain {
    Enum {
        values: Vec<Value>,
    },
    String {
        #[serde(default, deserialize_with = "deserialize_manifest_usize")]
        min_length: usize,
        #[serde(deserialize_with = "deserialize_manifest_usize")]
        max_length: usize,
    },
    Number {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        step: Option<f64>,
    },
    Boolean,
    Date {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<String>,
    },
    Datetime {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        min: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max: Option<String>,
    },
    BoundInput {
        port: String,
    },
    List {
        #[serde(default, deserialize_with = "deserialize_manifest_usize")]
        min_items: usize,
        #[serde(deserialize_with = "deserialize_manifest_usize")]
        max_items: usize,
        item: Box<RecordCreateValueDomain>,
    },
}

impl RecordCreateValueDomain {
    /// Pure value-shape and scalar/list-bound admission. A `bound_input`
    /// result still needs the host's binding-membership check for its port.
    pub fn admits(&self, value: &Value) -> bool {
        create_domain_admits(self, value)
    }

    pub fn bound_input_port(&self) -> Option<&str> {
        match self {
            Self::BoundInput { port } => Some(port),
            _ => None,
        }
    }
}

fn deserialize_manifest_usize<'de, D>(deserializer: D) -> Result<usize, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    let integer = value.as_u64().or_else(|| {
        value.as_f64().and_then(|value| {
            (value.is_finite() && value.fract() == 0.0 && value >= 0.0).then_some(value as u64)
        })
    });
    integer
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| serde::de::Error::custom("bound must be a non-negative integer"))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SlotDecl {
    pub domain: SlotDomain,
}

/// A slot's admissible operands.
///
/// `bound_input` is the only record domain there is: a record operand is
/// whatever the host resolves from the artifact's binding, optionally narrowed
/// to one declared input port.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SlotDomain {
    BoundInput {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        port: Option<String>,
    },
    /// An enumerated value domain. A literal is this at width one.
    Values { values: Vec<Value> },
}

impl SlotDomain {
    pub fn is_record(&self) -> bool {
        matches!(self, Self::BoundInput { .. })
    }

    /// Membership, at any width. One mechanism serves both a literal and a
    /// wide enumeration; only the member count differs.
    pub fn admits(&self, value: &Value) -> bool {
        match self {
            Self::BoundInput { .. } => false,
            Self::Values { values } => values.contains(value),
        }
    }

    /// The single admissible member, when the domain has exactly one. This is
    /// what makes a literal need no filling from the artifact.
    pub fn sole_member(&self) -> Option<&Value> {
        match self {
            Self::BoundInput { .. } => None,
            Self::Values { values } => values.first().filter(|_| values.len() == 1),
        }
    }
}

/// Where an entry's written value comes from: a literal, or a declared slot.
///
/// Both resolve to a [`SlotDomain`], so the host runs one membership check.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(tag = "from", rename_all = "snake_case", deny_unknown_fields)]
pub enum ValueSource {
    Literal { value: Value },
    Slot { slot: String },
}

impl ValueSource {
    /// The domain constraining this value — a literal is a domain of size one,
    /// materialized here so callers never special-case it.
    pub fn domain(&self, entry: &InteractionEntry) -> Option<SlotDomain> {
        match self {
            Self::Literal { value } => Some(SlotDomain::Values {
                values: vec![value.clone()],
            }),
            Self::Slot { slot } => entry
                .slots
                .get(slot)
                .map(|declaration| declaration.domain.clone()),
        }
    }

    pub fn slot_name(&self) -> Option<&str> {
        match self {
            Self::Literal { .. } => None,
            Self::Slot { slot } => Some(slot.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Manifest {
    Module(ModuleManifest),
    Artifact(ArtifactManifest),
}

impl Manifest {
    pub fn inputs(&self) -> &BTreeMap<String, InputDecl> {
        match self {
            Self::Module(value) => &value.inputs,
            Self::Artifact(value) => &value.inputs,
        }
    }

    pub fn module_inputs(&self) -> &BTreeMap<String, ModuleInputMap> {
        match self {
            Self::Module(value) => &value.module_inputs,
            Self::Artifact(value) => &value.module_inputs,
        }
    }

    pub fn capability_requests(&self) -> &[CapabilityRequest] {
        match self {
            Self::Module(value) => &value.capability_requests,
            Self::Artifact(value) => &value.capability_requests,
        }
    }

    pub fn normalized(&self) -> Value {
        match self {
            Self::Module(value) => serde_json::to_value(value).expect("module manifest"),
            Self::Artifact(value) => serde_json::to_value(value).expect("artifact manifest"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ModuleAddress {
    pub module_record_id: String,
    pub publication_event_id: String,
    pub source_sha256: String,
}

impl ModuleAddress {
    pub fn parse(specifier: &str) -> Result<Self, mdx::Failure> {
        const PREFIX: &str = "native:module/";
        let rest = specifier
            .strip_prefix(PREFIX)
            .ok_or_else(|| specifier_failure(specifier))?;
        let (module_id, rest) = rest
            .split_once("@event-")
            .ok_or_else(|| specifier_failure(specifier))?;
        let (publication_id, digest) = rest
            .split_once("?sha256=")
            .ok_or_else(|| specifier_failure(specifier))?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || !canonical_uuid(module_id)
            || !canonical_uuid(publication_id)
            || format!("{PREFIX}{module_id}@event-{publication_id}?sha256={digest}") != specifier
        {
            return Err(specifier_failure(specifier));
        }
        Ok(Self {
            module_record_id: module_id.into(),
            publication_event_id: publication_id.into(),
            source_sha256: digest.into(),
        })
    }

    #[cfg(test)]
    fn specifier(&self) -> String {
        format!(
            "native:module/{}@event-{}?sha256={}",
            self.module_record_id, self.publication_event_id, self.source_sha256
        )
    }
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|uuid| uuid.hyphenated().to_string() == value)
}

fn specifier_failure(specifier: &str) -> mdx::Failure {
    mdx::Failure::new(
        "module_specifier_invalid",
        "policy",
        "module imports must use the exact portable Native module grammar",
    )
    .detail("specifier", specifier.to_owned())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportName {
    pub exported: String,
    pub local: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ImportRef {
    pub specifier: String,
    pub address: ModuleAddress,
    pub names: Vec<ImportName>,
    pub source_range: Value,
    #[serde(skip)]
    pub compiled_specifier_start: usize,
    #[serde(skip)]
    pub compiled_specifier_end: usize,
}

#[derive(Clone, Debug)]
pub struct ParsedSource {
    pub source_bytes: usize,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub export_ranges: BTreeMap<String, Value>,
    pub manifest: Manifest,
    pub imports: Vec<ImportRef>,
    pub compiled: String,
    /// The validated, prefixed, `@scope`-wrapped author stylesheet, when the
    /// source declares `export const nativeStyles`. `None` is the ordinary
    /// case and must stay indistinguishable from a source written before this
    /// field existed — see `compiled_cache_key`.
    pub styles: Option<css::StyleSheet>,
}

impl ParsedSource {
    pub fn styles_sha256(&self) -> Option<&str> {
        self.styles.as_ref().map(|styles| styles.sha256.as_str())
    }

    /// The stylesheet's non-rejecting observations, as JSON.
    ///
    /// `css::Flag` exists so that novelty — an at-rule this validator does not
    /// know, a property it does not know, a function it does not know, an id
    /// selector it deliberately does not rewrite — is *visible* rather than
    /// silently allowed. That is only
    /// true if something outside `css.rs` can read it, so this is the
    /// conversion the render path uses to put the flags in `plan.styles`.
    /// Serialised here rather than derived on `Flag` because the crate takes
    /// no `serde` derive dependency for a two-field shape.
    pub fn styles_flags(&self) -> Vec<Value> {
        self.styles
            .as_ref()
            .map(|styles| {
                styles
                    .flags
                    .iter()
                    .map(|flag| json!({ "rule": flag.rule, "name": flag.name }))
                    .collect()
            })
            .unwrap_or_default()
    }
}

pub fn parse_module(source: &str) -> Result<ParsedSource, mdx::Failure> {
    parse(source, true)
}

pub fn parse_artifact(source: &str) -> Result<ParsedSource, mdx::Failure> {
    parse(source, false)
}

pub fn parse_artifact_cached(
    source: &str,
    partition: &str,
) -> Result<(ParsedSource, &'static str), mdx::Failure> {
    parse_cached(source, false, partition)
}

pub fn parse_module_cached(
    source: &str,
    partition: &str,
) -> Result<(ParsedSource, &'static str), mdx::Failure> {
    parse_cached(source, true, partition)
}

fn parse_cached(
    source: &str,
    module_source: bool,
    partition: &str,
) -> Result<(ParsedSource, &'static str), mdx::Failure> {
    let source_sha256 = mdx::sha256_hex(source.as_bytes());
    let key = format!(
        "{}:{}:{}:{}:{}",
        CACHE_NAMESPACE,
        ADAPTER_REVISION,
        mdx::sha256_hex(partition.as_bytes()),
        if module_source { "module" } else { "artifact" },
        source_sha256
    );
    let mut corrupt = false;
    {
        let mut cache = parsed_cache()
            .lock()
            .expect("v2 parsed cache lock poisoned");
        cache.clock = cache.clock.saturating_add(1);
        let now = cache.clock;
        if let Some(entry) = cache.entries.get_mut(&key) {
            if entry.parsed.source_sha256 == source_sha256
                && entry.compiled_sha256 == mdx::sha256_hex(entry.parsed.compiled.as_bytes())
            {
                entry.last_used = now;
                return Ok((entry.parsed.clone(), "hit"));
            }
        }
        if let Some(entry) = cache.entries.remove(&key) {
            cache.bytes = cache.bytes.saturating_sub(entry.bytes);
            corrupt = true;
        }
    }
    let parsed = parse(source, module_source)?;
    let bytes = source
        .len()
        .saturating_add(parsed.compiled.len())
        .saturating_add(
            parsed
                .styles
                .as_ref()
                .map_or(0, css::StyleSheet::cached_bytes),
        );
    if bytes <= MAX_CACHE_BYTES {
        let mut cache = parsed_cache()
            .lock()
            .expect("v2 parsed cache lock poisoned");
        while !cache.entries.is_empty()
            && (cache.entries.len() >= MAX_CACHE_ENTRIES
                || cache.bytes.saturating_add(bytes) > MAX_CACHE_BYTES)
        {
            let oldest = cache
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
                .expect("non-empty cache has an oldest entry");
            if let Some(entry) = cache.entries.remove(&oldest) {
                cache.bytes = cache.bytes.saturating_sub(entry.bytes);
            }
        }
        cache.clock = cache.clock.saturating_add(1);
        let last_used = cache.clock;
        cache.bytes = cache.bytes.saturating_add(bytes);
        cache.entries.insert(
            key,
            ParsedCacheEntry {
                compiled_sha256: mdx::sha256_hex(parsed.compiled.as_bytes()),
                parsed: parsed.clone(),
                bytes,
                last_used,
            },
        );
    }
    Ok((parsed, if corrupt { "rebuilt_corrupt" } else { "miss" }))
}

/// The compiled-graph cache key.
///
/// `styles_sha256` is the digest of the emitted author stylesheet, and is
/// **omitted entirely** when the artifact declares none — exactly the trick
/// `ArtifactManifest::interactions` plays with `skip_serializing_if`. A
/// no-styles artifact therefore hashes the same *field list* it hashed before
/// author CSS existed — not the same key: `ADAPTER_REVISION` moved 2 to 3 when
/// the field was added, and 3 to 4 for tier two, so every key in flight changes
/// on either, styled or not. What the omission buys is that no-styles artifacts
/// never pay for the field again, under this revision or any later one.
///
/// Adding the field is free *only* because of that revision bump. A later
/// change that adds a field without one would silently serve a stale graph.
/// The field order is part of the key: `styles_sha256` is appended after
/// `adapter_revision`, and moving it would change every styled artifact's key.
/// `compiled_cache_key_pins_the_field_order_for_a_styled_artifact` is the
/// golden that says so.
pub fn compiled_cache_key(
    root_body_sha256: &str,
    root_manifest_sha256: &str,
    dependency_closure_sha256: &str,
    compiler_lock_sha256: &str,
    styles_sha256: Option<&str>,
) -> String {
    let adapter_revision = ADAPTER_REVISION.to_string();
    let mut fields = vec![
        ("namespace", CACHE_NAMESPACE),
        ("root_body_sha256", root_body_sha256),
        ("root_manifest_sha256", root_manifest_sha256),
        ("dependency_closure_sha256", dependency_closure_sha256),
        ("runtime_id", RUNTIME_ID),
        ("compiler_lock_sha256", compiler_lock_sha256),
        ("compile_profile", "native.mdx.compile.v2"),
        ("component_policy", mdx::V2_COMPONENT_POLICY),
        ("named_input_abi", NAMED_INPUT_ABI),
        ("module_abi", MODULE_SCHEMA),
        ("executor", "rquickjs.quickjs-ng@0.11.0"),
        ("output_abi", mdx::SAFE_TREE_VERSION),
        ("diagnostic_contract", "native.artifact-diagnostic.v1"),
        ("limits_profile", "1"),
        ("adapter_revision", adapter_revision.as_str()),
    ];
    if let Some(styles_sha256) = styles_sha256 {
        fields.push(("styles_sha256", styles_sha256));
    }
    let mut digest = Sha256::new();
    for (name, value) in fields {
        for part in [name.as_bytes(), value.as_bytes()] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
    }
    hex::encode(digest.finalize())
}

pub fn graph_cache_lookup(key: &str, partition: &str) -> GraphCacheLookup {
    let storage_key = format!("{}:{key}", mdx::sha256_hex(partition.as_bytes()));
    let mut cache = compiled_graph_cache()
        .lock()
        .expect("v2 compiled graph cache lock poisoned");
    cache.clock = cache.clock.saturating_add(1);
    let now = cache.clock;
    if let Some(entry) = cache.entries.get_mut(&storage_key) {
        let valid = entry.root_sha256 == mdx::sha256_hex(entry.root.as_bytes())
            && entry.module_sha256.len() == entry.modules.len()
            && entry.modules.iter().all(|(name, source)| {
                entry.module_sha256.get(name) == Some(&mdx::sha256_hex(source.as_bytes()))
            });
        if valid {
            entry.last_used = now;
            return GraphCacheLookup::Hit {
                root: entry.root.clone(),
                modules: entry.modules.clone(),
            };
        }
    }
    if let Some(entry) = cache.entries.remove(&storage_key) {
        cache.bytes = cache.bytes.saturating_sub(entry.bytes);
        return GraphCacheLookup::Corrupt;
    }
    GraphCacheLookup::Miss
}

pub fn graph_cache_insert(
    key: &str,
    partition: &str,
    root: String,
    modules: HashMap<String, String>,
) {
    let storage_key = format!("{}:{key}", mdx::sha256_hex(partition.as_bytes()));
    let bytes = root
        .len()
        .saturating_add(modules.values().map(String::len).sum::<usize>());
    if bytes > MAX_CACHE_BYTES {
        return;
    }
    let mut cache = compiled_graph_cache()
        .lock()
        .expect("v2 compiled graph cache lock poisoned");
    while !cache.entries.is_empty()
        && (cache.entries.len() >= 64 || cache.bytes.saturating_add(bytes) > MAX_CACHE_BYTES)
    {
        let oldest = cache
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
            .expect("non-empty cache has oldest entry");
        if let Some(entry) = cache.entries.remove(&oldest) {
            cache.bytes = cache.bytes.saturating_sub(entry.bytes);
        }
    }
    cache.clock = cache.clock.saturating_add(1);
    let last_used = cache.clock;
    let module_sha256 = modules
        .iter()
        .map(|(name, source)| (name.clone(), mdx::sha256_hex(source.as_bytes())))
        .collect();
    cache.bytes = cache.bytes.saturating_add(bytes);
    cache.entries.insert(
        storage_key,
        CompiledGraphEntry {
            root_sha256: mdx::sha256_hex(root.as_bytes()),
            root,
            modules,
            module_sha256,
            bytes,
            last_used,
        },
    );
}

pub fn normalize_failure(mut failure: mdx::Failure) -> mdx::Failure {
    if let Some(details) = failure.details.as_object_mut() {
        details.insert("runtime".into(), json!(RUNTIME_ID));
        details.insert("adapter_revision".into(), json!(ADAPTER_REVISION));
    }
    failure
}

fn parse(source: &str, module_source: bool) -> Result<ParsedSource, mdx::Failure> {
    parse_inner(source, module_source).map_err(normalize_failure)
}

fn parse_inner(source: &str, module_source: bool) -> Result<ParsedSource, mdx::Failure> {
    let authored = authored_source(source)?;
    let compiled = mdx::compile_v2_source(source)?;
    let (ast, _source_map) = parse_javascript(&compiled)?;
    let mut policy = PolicyVisitor::default();
    ast.visit_with(&mut policy);
    if let Some(name) = policy.denied.into_iter().next() {
        return Err(mdx::Failure::new(
            "mdx_capability_denied",
            "policy",
            "native.mdx.v2 source references unavailable ambient authority",
        )
        .detail("binding", name));
    }
    if policy.dynamic_import {
        return Err(specifier_failure("import()"));
    }
    if policy.async_or_generator {
        return Err(mdx::Failure::new(
            "module_interface_incompatible",
            "inspection",
            "async, await, and generator paths are forbidden in native.mdx.v2",
        ));
    }
    // A drop is a bubbling browser gesture: dropping on an inner `DropTarget`
    // also fires the outer one, so a single gesture would commit two facet
    // writes. Nothing in the DOM contract forbids that nesting, so the
    // compiler does — at any depth, not just for a direct child, because an
    // intervening `Stack` changes nothing about how the event bubbles.
    //
    // This is the authored-tree half of the rule and the friendlier error: it
    // sees only the JSX the source writes literally, so a `DropTarget` a
    // helper component or an imported module returns is invisible here. The
    // rendered tree is where the rule is actually enforced — the same
    // `drop_target_not_nested` failure is raised from `mdx::validate_value`.
    //
    // The rule stops at `DropTarget`. A `FacetControl` inside a `DropTarget`
    // stays legal: it commits on change, and a drop gesture cannot also fire a
    // change handler, so that nesting is still one write per gesture from two
    // distinct gestures.
    if policy.nested_drop_target {
        return Err(mdx::Failure::new(
            "mdx_policy_violation",
            "policy",
            "a DropTarget may not appear inside another DropTarget: one drop gesture would commit two facet writes",
        )
        .detail("rule", "drop_target_not_nested"));
    }

    let manifest_name = if module_source {
        "nativeModule"
    } else {
        "nativeArtifact"
    };
    let mut manifest_value = None;
    let mut styles_source: Option<String> = None;
    let mut imports = Vec::new();
    let mut authored_import_index = 0usize;
    let mut exported_names = BTreeSet::new();
    let mut export_shapes = BTreeMap::<String, &'static str>::new();
    for item in &ast.body {
        let ModuleItem::ModuleDecl(decl) = item else {
            continue;
        };
        match decl {
            ModuleDecl::Import(import) => {
                let specifier = import.src.value.to_string();
                if matches!(
                    specifier.as_str(),
                    "native.mdx.v2/jsx-runtime" | "native.mdx.v2/provider"
                ) {
                    continue;
                }
                let authored_import =
                    authored.imports.get(authored_import_index).ok_or_else(|| {
                        mdx::Failure::new(
                            "mdx_compile_failed",
                            "inspection",
                            "compiled import has no exact authored MDX origin",
                        )
                    })?;
                authored_import_index += 1;
                if authored_import.specifier != specifier {
                    return Err(mdx::Failure::new(
                        "mdx_compile_failed",
                        "inspection",
                        "compiled import order does not match authored MDX imports",
                    )
                    .detail("source_range", authored_import.source_range.clone()));
                }
                if import.type_only || import.with.is_some() || import.specifiers.is_empty() {
                    return Err(specifier_failure(&specifier)
                        .detail("source_range", authored_import.source_range.clone()));
                }
                let address = ModuleAddress::parse(&specifier).map_err(|failure| {
                    failure.detail("source_range", authored_import.source_range.clone())
                })?;
                let mut names = Vec::with_capacity(import.specifiers.len());
                for import in &import.specifiers {
                    let ImportSpecifier::Named(named) = import else {
                        return Err(specifier_failure(&specifier)
                            .detail("source_range", authored_import.source_range.clone()));
                    };
                    if named.is_type_only {
                        return Err(specifier_failure(&specifier)
                            .detail("source_range", authored_import.source_range.clone()));
                    }
                    let exported = named
                        .imported
                        .as_ref()
                        .map(ModuleExportName::atom)
                        .unwrap_or(&named.local.sym)
                        .to_string();
                    names.push(ImportName {
                        exported,
                        local: named.local.sym.to_string(),
                    });
                }
                names.sort_by(|left, right| left.local.cmp(&right.local));
                imports.push(ImportRef {
                    source_range: authored_import.source_range.clone(),
                    compiled_specifier_start: import.src.span.lo.0.saturating_sub(1) as usize,
                    compiled_specifier_end: import.src.span.hi.0.saturating_sub(1) as usize,
                    specifier,
                    address,
                    names,
                });
            }
            ModuleDecl::ExportDecl(export) => match &export.decl {
                Decl::Var(vars) => {
                    for declaration in &vars.decls {
                        let Pat::Ident(binding) = &declaration.name else {
                            return Err(descriptor_failure("export destructuring is unsupported"));
                        };
                        let name = binding.id.sym.to_string();
                        if !exported_names.insert(name.clone()) {
                            return Err(descriptor_failure("source export is duplicated"));
                        }
                        if name == manifest_name {
                            if manifest_value.is_some() {
                                return Err(descriptor_failure("manifest export is duplicated"));
                            }
                            manifest_value = Some(static_json(
                                declaration.init.as_deref().ok_or_else(|| {
                                    descriptor_failure("manifest export requires an initializer")
                                })?,
                            )?);
                        } else if name == STYLES_EXPORT {
                            // Extracted exactly like the manifest, and for the
                            // same reason: it is a declaration about the
                            // artifact, read statically and never evaluated.
                            // It is deliberately not recorded in
                            // `export_shapes` — it is not part of any module
                            // interface, and a module may not declare it at
                            // all (see `validated_styles`).
                            if styles_source.is_some() {
                                return Err(descriptor_failure(
                                    "nativeStyles export is duplicated",
                                ));
                            }
                            let value =
                                static_json(declaration.init.as_deref().ok_or_else(|| {
                                    descriptor_failure(
                                        "nativeStyles export requires an initializer",
                                    )
                                })?)?;
                            let Value::String(source) = value else {
                                return Err(descriptor_failure(
                                    "nativeStyles must be a string literal or a \
                                     substitution-free template literal",
                                ));
                            };
                            styles_source = Some(source);
                        } else {
                            let shape = match declaration.init.as_deref() {
                                Some(Expr::Arrow(arrow))
                                    if !arrow.is_async && !arrow.is_generator =>
                                {
                                    "function"
                                }
                                Some(expr) if static_json(expr).is_ok() => "constant",
                                _ => "unsupported",
                            };
                            export_shapes.insert(name, shape);
                        }
                    }
                }
                Decl::Fn(function) => {
                    let name = function.ident.sym.to_string();
                    if !exported_names.insert(name.clone()) {
                        return Err(descriptor_failure("source export is duplicated"));
                    }
                    export_shapes.insert(
                        name,
                        if function.function.is_async || function.function.is_generator {
                            "unsupported"
                        } else {
                            "function"
                        },
                    );
                }
                _ => {
                    return Err(descriptor_failure(
                        "classes and typed exports are unsupported",
                    ))
                }
            },
            ModuleDecl::ExportNamed(export) => {
                // Only `export const nativeStyles = ...` above is read. An
                // export clause naming it — `export { sheet as nativeStyles }`
                // — never reaches that branch, so it used to produce a
                // silently unstyled artifact and no diagnostic, while
                // declaring the export *twice* was rejected outright. The
                // manifest cannot have that asymmetry, because a missing
                // manifest is itself an error. Name the unsupported spellings
                // instead of ignoring them. (A re-export already failed on its
                // specifier below; it is checked here first so it fails for
                // the reason the author needs to hear.)
                for specifier in &export.specifiers {
                    let exported = match specifier {
                        ExportSpecifier::Named(named) => {
                            exported_name(named.exported.as_ref().unwrap_or(&named.orig))
                        }
                        ExportSpecifier::Default(default) => default.exported.sym.to_string(),
                        ExportSpecifier::Namespace(namespace) => exported_name(&namespace.name),
                    };
                    if exported == STYLES_EXPORT {
                        return Err(descriptor_failure(
                            "nativeStyles must be declared as `export const nativeStyles = \"...\"`: \
                             an export clause or re-export is not read",
                        )
                        .detail("rule", "styles_export_declaration"));
                    }
                }
                if let Some(src) = &export.src {
                    return Err(specifier_failure(src.value.as_ref()));
                }
            }
            ModuleDecl::ExportAll(_) => return Err(specifier_failure("export *")),
            _ => {}
        }
    }
    if authored_import_index != authored.imports.len() {
        return Err(mdx::Failure::new(
            "mdx_compile_failed",
            "inspection",
            "authored MDX import has no exact compiled occurrence",
        )
        .detail(
            "source_range",
            authored.imports[authored_import_index].source_range.clone(),
        ));
    }
    let manifest_value = manifest_value
        .ok_or_else(|| descriptor_failure(format!("missing export const {manifest_name}")))?;
    let manifest = if module_source {
        let value: ModuleManifest = serde_json::from_value(manifest_value).map_err(|error| {
            descriptor_failure(format!("nativeModule manifest is invalid: {error}"))
        })?;
        validate_module_manifest(
            &value,
            &imports,
            &export_shapes,
            &policy.required_capabilities,
        )?;
        Manifest::Module(value)
    } else {
        let value: ArtifactManifest = serde_json::from_value(manifest_value).map_err(|error| {
            descriptor_failure(format!("nativeArtifact manifest is invalid: {error}"))
        })?;
        validate_artifact_manifest(&value, &imports, &policy.required_capabilities)?;
        Manifest::Artifact(value)
    };
    let styles = match styles_source {
        Some(source) => Some(validated_styles(&source, &manifest)?),
        None => None,
    };
    let normalized = manifest.normalized();
    Ok(ParsedSource {
        source_bytes: source.len(),
        source_sha256: mdx::sha256_hex(source.as_bytes()),
        manifest_sha256: mdx::sha256_hex(canonical_json_bytes(&normalized).as_slice()),
        export_ranges: authored.exports,
        manifest,
        imports,
        compiled,
        styles,
    })
}

/// Turns a `css::Failure` into the failure shape the artifact host reports.
///
/// The code, message and named `rule` are carried across unchanged, so a
/// rejection still says which CSS rule refused the sheet. `normalize_failure`
/// then overwrites `runtime`/`adapter_revision` with this adapter's, which is
/// why the CSS validator's own identifier is preserved separately.
fn css_failure(failure: css::Failure) -> mdx::Failure {
    mdx::Failure {
        code: failure.code,
        message: failure.message,
        details: failure.details,
    }
    .detail("css_runtime", css::RUNTIME_ID)
}

/// Validates `export const nativeStyles` against the artifact that declares it.
///
/// One gate precedes the CSS validator itself: **artifacts only**. A module's
/// exports are consumed by whichever artifact imports them, so a module
/// stylesheet would have no unambiguous scope root and would silently do
/// nothing. Refuse it rather than accept and ignore.
///
/// **Tier one had a second gate here, and it is gone.** `styles_require_read_only`
/// rejected any artifact that declared both `nativeStyles` and a non-empty
/// `interactions`. Removing a fail-closed refusal is the security-relevant part
/// of tier two, so what the gate stood in for is written here rather than left
/// as an absence.
///
/// The gate was a placeholder for one unanswered question: can author CSS
/// disguise a host-owned affordance — make an interactive control appear to do
/// something other than what it does? Two things answer it now, and neither is
/// a check in this function:
///
/// 1. **Closed host chrome is out of scope, mechanically.** `STYLE_SCOPE_LIMIT`
///    is `.native-interactive`, the marker the host puts on interactive controls
///    and authenticated chart presentation. `@scope (root) to (limit)` excludes
///    the limit element itself as well
///    as its subtree. A marked label is therefore unmatchable from the author
///    sheet — `!important` included, because the rule never enters the cascade
///    in the first place. So author CSS cannot restyle it, cannot rewrite it
///    with `content`, and cannot inherit into it. This holds for every artifact
///    the adapter emits, read-only or writable, and it does not depend on the
///    manifest.
/// 2. **Placement presentation belongs to the artifact.** Decision `e3fb337b`
///    removes persistent host labels, raw effects and status chrome from
///    `DropTarget` and `RecordCard`. Placement authority remains in the
///    manifest, availability, version and audit machinery; it is not asserted
///    by host pixels inside the authored composition. An author sheet may move,
///    resize or hide a target, and that visual risk is accepted at this product
///    stage without adding a post-write integrity disclosure.
///
/// So the gate is not relaxed on the grounds that the risk evaporated. It is
/// replaced by a narrower property that is enforced for every sheet by the
/// scope wrapper — an author rule cannot match the remaining marked controls —
/// instead of by a manifest-shaped proxy that only ever approximated it.
fn validated_styles(source: &str, manifest: &Manifest) -> Result<css::StyleSheet, mdx::Failure> {
    if !matches!(manifest, Manifest::Artifact(_)) {
        return Err(descriptor_failure(
            "nativeStyles is an artifact export; a module cannot declare author CSS",
        ));
    }
    css::validate(
        source,
        mdx::AUTHOR_CLASS_PREFIX,
        STYLE_SCOPE_ROOT,
        STYLE_SCOPE_LIMIT,
    )
    .map_err(css_failure)
}

#[derive(Debug)]
struct AuthoredImport {
    specifier: String,
    source_range: Value,
}

#[derive(Debug, Default)]
struct AuthoredSource {
    imports: Vec<AuthoredImport>,
    exports: BTreeMap<String, Value>,
}

fn authored_source(source: &str) -> Result<AuthoredSource, mdx::Failure> {
    let mut imports = Vec::new();
    let mut exports = BTreeMap::new();
    for esm in mdx::authored_v2_esm(source)? {
        let cm: Lrc<SourceMap> = Default::default();
        let file = cm.new_source_file(
            FileName::Custom("native.mdx.v2.authored.esm".into()).into(),
            esm.source.clone(),
        );
        let lexer = Lexer::new(
            Syntax::Es(EsSyntax {
                jsx: true,
                ..Default::default()
            }),
            Default::default(),
            StringInput::from(&*file),
            None,
        );
        let mut parser = Parser::new_from(lexer);
        let module = parser.parse_module().map_err(|_| {
            mdx::Failure::new(
                "mdx_compile_failed",
                "inspection",
                "authored MDX ESM could not be inspected",
            )
        })?;
        if !parser.take_errors().is_empty() {
            return Err(mdx::Failure::new(
                "mdx_compile_failed",
                "inspection",
                "authored MDX ESM contained recoverable syntax errors",
            ));
        }
        for item in module.body {
            let ModuleItem::ModuleDecl(decl) = item else {
                continue;
            };
            let span = match &decl {
                ModuleDecl::Import(import) => import.span,
                ModuleDecl::ExportDecl(export) => export.span,
                _ => continue,
            };
            let local_start = span.lo.0.saturating_sub(1) as usize;
            let local_end = span.hi.0.saturating_sub(1) as usize;
            let start = esm.start_offset.saturating_add(local_start);
            let end = esm.start_offset.saturating_add(local_end);
            if start > end
                || end > source.len()
                || !source.is_char_boundary(start)
                || !source.is_char_boundary(end)
            {
                return Err(mdx::Failure::new(
                    "mdx_compile_failed",
                    "inspection",
                    "authored MDX import position is invalid",
                ));
            }
            let source_range = authored_offset_range(source, start, end);
            match decl {
                ModuleDecl::Import(import) => imports.push(AuthoredImport {
                    specifier: import.src.value.to_string(),
                    source_range,
                }),
                ModuleDecl::ExportDecl(export) => match export.decl {
                    Decl::Fn(function) => {
                        exports.insert(function.ident.sym.to_string(), source_range);
                    }
                    Decl::Var(vars) => {
                        for declaration in vars.decls {
                            if let Pat::Ident(binding) = declaration.name {
                                exports.insert(binding.id.sym.to_string(), source_range.clone());
                            }
                        }
                    }
                    _ => {}
                },
                _ => unreachable!("authored declaration was filtered above"),
            }
        }
    }
    Ok(AuthoredSource { imports, exports })
}

fn parse_javascript(source: &str) -> Result<(swc_ecma_ast::Module, Lrc<SourceMap>), mdx::Failure> {
    let cm: Lrc<SourceMap> = Default::default();
    let file = cm.new_source_file(
        FileName::Custom("native.mdx.v2.compiled.js".into()).into(),
        source.to_owned(),
    );
    let lexer = Lexer::new(
        Syntax::Es(Default::default()),
        Default::default(),
        StringInput::from(&*file),
        None,
    );
    let mut parser = Parser::new_from(lexer);
    let module = parser.parse_module().map_err(|_| {
        mdx::Failure::new(
            "mdx_compile_failed",
            "inspection",
            "compiled MDX could not be inspected",
        )
    })?;
    if !parser.take_errors().is_empty() {
        return Err(mdx::Failure::new(
            "mdx_compile_failed",
            "inspection",
            "compiled MDX contained recoverable syntax errors",
        ));
    }
    Ok((module, cm))
}

#[derive(Default)]
struct PolicyVisitor {
    denied: BTreeSet<String>,
    dynamic_import: bool,
    required_capabilities: BTreeSet<String>,
    async_or_generator: bool,
    /// Depth of the enclosing `DropTarget` JSX calls, so the nesting rule
    /// below is a subtree test rather than a direct-child test.
    drop_target_depth: usize,
    nested_drop_target: bool,
}

impl Visit for PolicyVisitor {
    fn visit_ident(&mut self, ident: &swc_ecma_ast::Ident) {
        const DENIED: &[&str] = &[
            "globalThis",
            "window",
            "document",
            "navigator",
            "location",
            "fetch",
            "XMLHttpRequest",
            "WebSocket",
            "EventSource",
            "process",
            "require",
            "eval",
            "Function",
            "Date",
            "performance",
            "setTimeout",
            "setInterval",
            "queueMicrotask",
            "crypto",
            "Promise",
            "localStorage",
            "sessionStorage",
            "indexedDB",
            "caches",
            "Worker",
            "WebAssembly",
            "Intl",
            "__nativeBridge",
            "__nativeOriginEnter",
            "__nativeOriginCapture",
            "__nativeOriginSelect",
            "__nativeOriginClear",
            "__nativeOriginExit",
        ];
        let name = ident.sym.as_ref();
        if DENIED.contains(&name) {
            self.denied.insert(name.to_owned());
        }
        if matches!(name, "RecordList" | "RecordTable" | "RecordCard" | "Field") {
            self.required_capabilities
                .insert("navigation.record.user_gesture".into());
        }
    }

    fn visit_call_expr(&mut self, call: &swc_ecma_ast::CallExpr) {
        if matches!(call.callee, Callee::Import(_)) {
            self.dynamic_import = true;
        }
        let jsx_factory = matches!(
            &call.callee,
            Callee::Expr(callee) if matches!(
                callee.as_ref(),
                Expr::Ident(name) if matches!(name.sym.as_ref(), "_jsx" | "_jsxs" | "_jsxDEV")
            )
        );
        let mut drop_target = false;
        if jsx_factory {
            if let Some(first) = call.args.first().map(|arg| arg.expr.as_ref()) {
                let compiled_tag = match first {
                    Expr::Lit(Lit::Str(tag)) => Some(tag.value.as_ref()),
                    // MDX destructures provider components into locals, so a
                    // native component reaches the factory as a bare ident.
                    Expr::Ident(tag) => Some(tag.sym.as_ref()),
                    Expr::Member(member) => match &member.prop {
                        swc_ecma_ast::MemberProp::Ident(tag) => Some(tag.sym.as_ref()),
                        _ => None,
                    },
                    _ => None,
                };
                if let Some(compiled_tag) = compiled_tag {
                    match compiled_tag {
                        "a" => {
                            self.required_capabilities
                                .insert("navigation.external.user_gesture".into());
                        }
                        "RecordList" | "RecordTable" | "RecordCard" | "Field" => {
                            self.required_capabilities
                                .insert("navigation.record.user_gesture".into());
                        }
                        _ => {}
                    }
                    if compiled_tag == "DropTarget" {
                        drop_target = true;
                        if self.drop_target_depth > 0 {
                            self.nested_drop_target = true;
                        }
                    }
                }
            }
        }
        if drop_target {
            self.drop_target_depth += 1;
        }
        call.visit_children_with(self);
        if drop_target {
            self.drop_target_depth -= 1;
        }
    }

    fn visit_jsx_opening_element(&mut self, element: &swc_ecma_ast::JSXOpeningElement) {
        if matches!(
            &element.name,
            swc_ecma_ast::JSXElementName::Ident(name) if name.sym.as_ref() == "a"
        ) {
            self.required_capabilities
                .insert("navigation.external.user_gesture".into());
        }
        element.visit_children_with(self);
    }

    fn visit_function(&mut self, function: &swc_ecma_ast::Function) {
        if function.is_async || function.is_generator {
            self.async_or_generator = true;
        }
        function.visit_children_with(self);
    }

    fn visit_arrow_expr(&mut self, arrow: &swc_ecma_ast::ArrowExpr) {
        if arrow.is_async || arrow.is_generator {
            self.async_or_generator = true;
        }
        arrow.visit_children_with(self);
    }

    fn visit_await_expr(&mut self, expression: &swc_ecma_ast::AwaitExpr) {
        self.async_or_generator = true;
        expression.visit_children_with(self);
    }

    fn visit_yield_expr(&mut self, expression: &swc_ecma_ast::YieldExpr) {
        self.async_or_generator = true;
        expression.visit_children_with(self);
    }
}

fn static_json(expr: &Expr) -> Result<Value, mdx::Failure> {
    match expr {
        Expr::Lit(Lit::Str(value)) => Ok(Value::String(value.value.to_string())),
        Expr::Lit(Lit::Bool(value)) => Ok(Value::Bool(value.value)),
        Expr::Lit(Lit::Null(_)) => Ok(Value::Null),
        Expr::Lit(Lit::Num(value)) => serde_json::Number::from_f64(value.value)
            .map(Value::Number)
            .ok_or_else(|| descriptor_failure("manifest numbers must be finite")),
        Expr::Unary(unary) if unary.op == UnaryOp::Minus => {
            let Expr::Lit(Lit::Num(value)) = unary.arg.as_ref() else {
                return Err(descriptor_failure(
                    "manifest unary expressions are forbidden",
                ));
            };
            serde_json::Number::from_f64(-value.value)
                .map(Value::Number)
                .ok_or_else(|| descriptor_failure("manifest numbers must be finite"))
        }
        Expr::Array(array) => array
            .elems
            .iter()
            .map(|item| {
                let item = item
                    .as_ref()
                    .ok_or_else(|| descriptor_failure("manifest array holes are forbidden"))?;
                if item.spread.is_some() {
                    return Err(descriptor_failure("manifest spreads are forbidden"));
                }
                static_json(&item.expr)
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        Expr::Object(object) => {
            let mut output = Map::new();
            for property in &object.props {
                let PropOrSpread::Prop(property) = property else {
                    return Err(descriptor_failure("manifest spreads are forbidden"));
                };
                let Prop::KeyValue(property) = property.as_ref() else {
                    return Err(descriptor_failure(
                        "manifest getters, methods, and shorthand are forbidden",
                    ));
                };
                let key = match &property.key {
                    PropName::Ident(value) => value.sym.to_string(),
                    PropName::Str(value) => value.value.to_string(),
                    _ => return Err(descriptor_failure("manifest computed keys are forbidden")),
                };
                if output.contains_key(&key) {
                    return Err(descriptor_failure(format!(
                        "manifest key '{key}' is duplicated"
                    )));
                }
                output.insert(key, static_json(&property.value)?);
            }
            Ok(Value::Object(output))
        }
        Expr::Paren(value) => static_json(&value.expr),
        // A substitution-free template literal is a string constant with
        // newlines the author did not have to escape, which is the difference
        // between a readable stylesheet and an unreadable one. A literal with
        // any substitution is not static — its value would depend on evaluating
        // an expression — and the whole declaration model rests on never
        // evaluating a declaration, so those stay rejected. `exprs.is_empty()`
        // and exactly one quasi are the same condition stated twice on purpose:
        // a well-formed template always has one more quasi than substitutions,
        // and this arm should not have to trust that.
        Expr::Tpl(template) if template.exprs.is_empty() && template.quasis.len() == 1 => {
            let quasi = &template.quasis[0];
            // `cooked` is None only when the literal contains an invalid escape
            // sequence, which has no string value to take.
            let value = quasi.cooked.as_ref().ok_or_else(|| {
                descriptor_failure("manifest template literals must not contain invalid escapes")
            })?;
            Ok(Value::String(value.to_string()))
        }
        Expr::Tpl(_) => Err(descriptor_failure(
            "manifest template literals must have no substitutions",
        )),
        Expr::TaggedTpl(_) => Err(descriptor_failure(
            "manifest tagged template literals are forbidden",
        )),
        _ => Err(descriptor_failure(
            "manifest must contain only static JSON-literal values",
        )),
    }
}

fn validate_module_manifest(
    manifest: &ModuleManifest,
    imports: &[ImportRef],
    export_shapes: &BTreeMap<String, &'static str>,
    required_capabilities: &BTreeSet<String>,
) -> Result<(), mdx::Failure> {
    if manifest.schema != MODULE_SCHEMA {
        return Err(descriptor_failure("unsupported nativeModule schema"));
    }
    validate_inputs(&manifest.inputs)?;
    if manifest.exports.is_empty() {
        return Err(descriptor_failure("nativeModule exports must not be empty"));
    }
    for (name, interface) in &manifest.exports {
        valid_export_name(name)?;
        if !matches!(
            interface.kind.as_str(),
            "component" | "function" | "constant"
        ) {
            return Err(descriptor_failure(format!(
                "module export '{name}' has unsupported kind"
            )));
        }
        let actual = export_shapes.get(name).copied().unwrap_or("missing");
        let compatible = match interface.kind.as_str() {
            "constant" => actual == "constant",
            "component" | "function" => actual == "function",
            _ => false,
        };
        if !compatible {
            return Err(mdx::Failure::new(
                "module_interface_incompatible",
                "manifest",
                format!("export '{name}' does not match its declared interface"),
            ));
        }
        match interface.kind.as_str() {
            "component" if !interface.args.is_empty() || interface.result.is_some() => {
                return Err(mdx::Failure::new(
                    "module_interface_incompatible",
                    "manifest",
                    format!("component export '{name}' must declare only its props schema"),
                ));
            }
            "function" if !interface.props.is_empty() || interface.result.is_none() => {
                return Err(mdx::Failure::new(
                    "module_interface_incompatible",
                    "manifest",
                    format!("function export '{name}' requires args/result schemas and no props"),
                ));
            }
            "constant"
                if !interface.props.is_empty()
                    || !interface.args.is_empty()
                    || interface.result.is_none() =>
            {
                return Err(mdx::Failure::new(
                    "module_interface_incompatible",
                    "manifest",
                    format!("constant export '{name}' requires exactly one result schema"),
                ));
            }
            _ => {}
        }
        let mut seen = BTreeSet::new();
        for port in &interface.uses_inputs {
            if !manifest.inputs.contains_key(port) || !seen.insert(port) {
                return Err(mdx::Failure::new(
                    "module_interface_incompatible",
                    "manifest",
                    format!("export '{name}' names an invalid input port"),
                ));
            }
        }
    }
    validate_module_input_maps(&manifest.module_inputs, imports, &manifest.inputs)?;
    let forwarded = manifest
        .module_inputs
        .values()
        .flat_map(|mapping| mapping.ports.values())
        .collect::<BTreeSet<_>>();
    for port in manifest.inputs.keys() {
        let used = manifest
            .exports
            .values()
            .any(|interface| interface.uses_inputs.contains(port));
        if !used && !forwarded.contains(port) {
            return Err(mdx::Failure::new(
                "module_input_unused",
                "manifest",
                format!("module input '{port}' is unused"),
            ));
        }
    }
    validate_capabilities(
        &manifest.capability_requests,
        &manifest.inputs,
        required_capabilities,
    )
}

fn validate_artifact_manifest(
    manifest: &ArtifactManifest,
    imports: &[ImportRef],
    required_capabilities: &BTreeSet<String>,
) -> Result<(), mdx::Failure> {
    if manifest.schema != ARTIFACT_SCHEMA {
        return Err(descriptor_failure("unsupported nativeArtifact schema"));
    }
    validate_inputs(&manifest.inputs)?;
    validate_module_input_maps(&manifest.module_inputs, imports, &manifest.inputs)?;
    let mapped = manifest
        .module_inputs
        .values()
        .flat_map(|mapping| mapping.ports.values())
        .collect::<BTreeSet<_>>();
    for (name, input) in &manifest.inputs {
        if !input.expose_to_root && !mapped.contains(name) {
            return Err(mdx::Failure::new(
                "named_input_unused",
                "manifest",
                format!("artifact input '{name}' is unused"),
            ));
        }
        if input.expose_to_root
            && !manifest.capability_requests.iter().any(|request| {
                request.capability == "input.read"
                    && request.scope.get("port").and_then(Value::as_str) == Some(name.as_str())
            })
        {
            return Err(mdx::Failure::new(
                "module_capability_denied",
                "manifest",
                format!("root input '{name}' is exposed without an exact input.read request"),
            ));
        }
    }
    validate_interactions(&manifest.interactions, &manifest.inputs)?;
    validate_capabilities(
        &manifest.capability_requests,
        &manifest.inputs,
        required_capabilities,
    )
}

pub const MAX_INTERACTION_ENTRIES: usize = 64;
pub const MAX_ENTRY_SLOTS: usize = 8;
pub const MAX_DOMAIN_MEMBERS: usize = 256;
pub const MAX_CREATE_VALUES: usize = 64;
pub const MAX_CREATE_INPUTS: usize = 32;
pub const MAX_CREATE_LIST_ITEMS: usize = 64;
pub const MAX_CREATE_STRING_LENGTH: usize = 65_536;
const MAX_LABEL_BYTES: usize = 120;
pub(crate) const MAX_FACET_KEY_BYTES: usize = 128;

/// Facet keys the engine HARD-DISPATCHES on, and which an artifact may
/// therefore never name.
///
/// This is a superset of the engine's own reserved list, and the difference is
/// the point:
///
/// * `archived` is owned by `archive_record`, which requires Manage and emits
///   the byte-identical `facet.set{key:"archived",value:"true"}` this path
///   could otherwise emit after checking only Edit;
/// * `blob_ref` is owned by the attachment tools and would let a declared entry
///   forge an attachment binding;
/// * `runtime` is an ORDINARY open facet the engine nonetheless dispatches on —
///   it selects the interpreter for a Program and the adapter for an artifact,
///   and the prospective-body validators run at the write that sets it. A
///   declared entry setting it would leave a module whose declared interpreter
///   no longer matches its body, or an artifact flipped to a runtime its body
///   never validated against.
///
/// Reserved is a claim about who may configure a key; dispatched is a claim
/// about what the engine does with it. An artifact must stay off both.
///
/// This crate cannot depend on the engine, so the list is duplicated here and a
/// host test (`engine_dispatched_facet_keys_cover_the_engine_contract`) fails
/// if the two drift.
pub const ENGINE_DISPATCHED_FACET_KEYS: [&str; 4] =
    ["archived", "blob_ref", "runtime", "canvas.promoted_from"];
pub const RECORD_CREATE_FIELD_KEYS: [&str; 6] = [
    "name",
    "body",
    "summary",
    "lifecycle",
    "persistence",
    "maturity",
];
pub const RECORD_CREATE_SPINE_FACET_KEYS: [&str; 4] =
    ["lifecycle", "owner", "persistence", "maturity"];

/// Compile-time validation of the declared interaction entry set. Every
/// diagnostic names the failing entry, in the message and in `entry_id`, so an
/// author is never told only that "an entry" is wrong.
fn validate_interactions(
    entries: &[InteractionEntry],
    inputs: &BTreeMap<String, InputDecl>,
) -> Result<(), mdx::Failure> {
    if entries.len() > MAX_INTERACTION_ENTRIES {
        return Err(mdx::Failure::new(
            "interaction_entry_invalid",
            "manifest",
            format!("artifact declares more than {MAX_INTERACTION_ENTRIES} interaction entries"),
        ));
    }
    let mut seen = BTreeSet::new();
    for entry in entries {
        let failure = |message: String| {
            Err(mdx::Failure::new(
                "interaction_entry_invalid",
                "manifest",
                format!("interaction entry '{}': {message}", entry.id),
            )
            .detail("entry_id", entry.id.clone()))
        };
        if !valid_entry_id(&entry.id) {
            return Err(mdx::Failure::new(
                "interaction_entry_invalid",
                "manifest",
                format!(
                    "interaction entry id '{}' is not a stable identifier",
                    entry.id
                ),
            )
            .detail("entry_id", entry.id.clone()));
        }
        if !seen.insert(entry.id.as_str()) {
            return failure("id is declared twice in this body".into());
        }
        if entry.label.trim().is_empty()
            || entry.label.len() > MAX_LABEL_BYTES
            || entry.label.chars().any(char::is_control)
        {
            return failure("label is blank, too long, or contains control characters".into());
        }
        if entry.effect == InteractionEffect::RecordCreate {
            if !entry.slots.is_empty() || !entry.facet.is_empty() || entry.value.is_some() {
                return failure(
                    "record.create cannot declare facet operands or legacy slots".into(),
                );
            }
            let Some(create) = &entry.create else {
                return failure("record.create declares no create envelope".into());
            };
            validate_record_create(create, inputs).map_err(|message| {
                mdx::Failure::new(
                    "interaction_entry_invalid",
                    "manifest",
                    format!("interaction entry '{}': {message}", entry.id),
                )
                .detail("entry_id", entry.id.clone())
            })?;
            continue;
        }
        if entry.create.is_some() {
            return failure(format!(
                "{} cannot declare a record.create envelope",
                entry.effect.as_str()
            ));
        }
        if !valid_facet_key(&entry.facet) {
            return failure("facet key is blank, too long, or contains control characters".into());
        }
        if ENGINE_DISPATCHED_FACET_KEYS.contains(&entry.facet.as_str()) {
            return failure(format!(
                "facet '{}' is engine-dispatched and is written only by the tool that owns it",
                entry.facet
            ));
        }
        if entry.slots.len() > MAX_ENTRY_SLOTS {
            return failure(format!("declares more than {MAX_ENTRY_SLOTS} slots"));
        }
        let mut record_slots = entry
            .slots
            .iter()
            .filter(|(_, declaration)| declaration.domain.is_record());
        let Some((record_slot, record_declaration)) = record_slots.next() else {
            return failure(
                "declares no bound_input slot, so it names no record to write to".into(),
            );
        };
        if let Some((extra, _)) = record_slots.next() {
            return failure(format!(
                "declares more than one bound_input slot ('{record_slot}' and '{extra}'); the entry writes to exactly one record"
            ));
        }
        if let SlotDomain::BoundInput { port: Some(port) } = &record_declaration.domain {
            let Some(input) = inputs.get(port) else {
                return failure(format!(
                    "bound_input slot names undeclared input port '{port}'"
                ));
            };
            if input.envelope != COLLECTION_ENVELOPE {
                return failure(format!(
                    "bound_input slot names non-record input port '{port}'"
                ));
            }
        } else if !inputs
            .values()
            .any(|input| input.envelope == COLLECTION_ENVELOPE)
        {
            return failure("unscoped bound_input slot has no record input port".into());
        }
        for (name, declaration) in &entry.slots {
            if !valid_port(name) {
                return failure(format!("slot name '{name}' is not a stable identifier"));
            }
            if let SlotDomain::Values { values } = &declaration.domain {
                if values.is_empty() || values.len() > MAX_DOMAIN_MEMBERS {
                    return failure(format!(
                        "slot '{name}' declares {} domain members (expected 1..={MAX_DOMAIN_MEMBERS})",
                        values.len()
                    ));
                }
                // A facet value is a string, a number or an object — the
                // stored form has no other case. Admitting a boolean here would
                // carry it all the way to the write path, which has no
                // representation for it.
                if values.iter().any(|value| {
                    !matches!(
                        value,
                        Value::String(_) | Value::Number(_) | Value::Object(_)
                    )
                }) {
                    return failure(format!(
                        "slot '{name}' declares a domain member that is not a string, number or object"
                    ));
                }
            }
        }
        match (entry.effect, &entry.value) {
            (InteractionEffect::FacetSet, None) => {
                return failure("facet.set declares no value".into())
            }
            (InteractionEffect::FacetUnset, Some(_)) => {
                return failure("facet.unset declares a value, which it cannot write".into())
            }
            (_, Some(ValueSource::Literal { value })) => {
                if !matches!(
                    value,
                    Value::String(_) | Value::Number(_) | Value::Object(_)
                ) {
                    return failure("value literal is not a string, number or object".into());
                }
            }
            (_, Some(ValueSource::Slot { slot })) => {
                let Some(declaration) = entry.slots.get(slot) else {
                    return failure(format!("value names undeclared slot '{slot}'"));
                };
                if declaration.domain.is_record() {
                    return failure(format!(
                        "value names record slot '{slot}'; a record is not a facet value"
                    ));
                }
            }
            _ => {}
        }
        for (name, declaration) in &entry.slots {
            let referenced = declaration.domain.is_record()
                || entry.value.as_ref().and_then(ValueSource::slot_name) == Some(name.as_str());
            if !referenced {
                return failure(format!("slot '{name}' is declared but unused"));
            }
        }
    }
    Ok(())
}

fn validate_record_create(
    create: &RecordCreateDecl,
    inputs: &BTreeMap<String, InputDecl>,
) -> Result<(), String> {
    let mut invocation_names = BTreeSet::new();
    match &create.destination {
        RecordCreateDestination::Literal { record_id } => {
            if !valid_create_name(record_id) {
                return Err("literal destination record id is blank, too long, or contains control characters".into());
            }
        }
        RecordCreateDestination::BoundInput { port } => {
            require_collection_port(port, inputs, "destination")?;
        }
    }
    validate_shape_discriminator("type", &create.shape.record_type, inputs)?;
    validate_shape_discriminator("kind", &create.shape.kind, inputs)?;
    register_create_input("type", &create.shape.record_type, &mut invocation_names)?;
    register_create_input("kind", &create.shape.kind, &mut invocation_names)?;
    if create.shape.fields.len() + create.shape.facets.len() > MAX_CREATE_VALUES {
        return Err(format!(
            "create shape declares more than {MAX_CREATE_VALUES} fields and facets"
        ));
    }
    for (key, value) in &create.shape.fields {
        if !RECORD_CREATE_FIELD_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "field '{key}' is not an ordinary record creation field"
            ));
        }
        validate_create_value(&format!("field '{key}'"), value, inputs)?;
        let string_domain = match &value.domain {
            RecordCreateValueDomain::String { .. } => true,
            RecordCreateValueDomain::Enum { values } => values.iter().all(Value::is_string),
            _ => false,
        };
        if !string_domain || matches!(value.source, RecordCreateValueSource::BoundInput { .. }) {
            return Err(format!("field '{key}' must resolve to a string"));
        }
        register_create_input(&format!("field '{key}'"), value, &mut invocation_names)?;
    }
    for (key, value) in &create.shape.facets {
        if !valid_facet_key(key) {
            return Err(format!("facet '{key}' has an invalid key"));
        }
        if ENGINE_DISPATCHED_FACET_KEYS.contains(&key.as_str())
            || RECORD_CREATE_SPINE_FACET_KEYS.contains(&key.as_str())
        {
            return Err(format!("facet '{key}' is engine-reserved or spine-owned"));
        }
        if create.shape.fields.contains_key(key) {
            return Err(format!("'{key}' is declared as both a field and facet"));
        }
        validate_create_value(&format!("facet '{key}'"), value, inputs)?;
        register_create_input(&format!("facet '{key}'"), value, &mut invocation_names)?;
    }
    if invocation_names.len() > MAX_CREATE_INPUTS {
        return Err(format!(
            "create shape declares more than {MAX_CREATE_INPUTS} invocation inputs"
        ));
    }
    Ok(())
}

fn register_create_input<'a>(
    context: &str,
    value: &'a RecordCreateValue,
    names: &mut BTreeSet<&'a str>,
) -> Result<(), String> {
    let name = match &value.source {
        RecordCreateValueSource::Literal { .. } => return Ok(()),
        RecordCreateValueSource::Input { input } => input.as_str(),
        RecordCreateValueSource::BoundInput { slot } => slot.as_str(),
    };
    if !names.insert(name) {
        return Err(format!(
            "{context} reuses invocation input '{name}'; each declared input must be unique"
        ));
    }
    Ok(())
}

fn validate_shape_discriminator(
    name: &str,
    value: &RecordCreateValue,
    inputs: &BTreeMap<String, InputDecl>,
) -> Result<(), String> {
    validate_create_value(name, value, inputs)?;
    match (&value.source, &value.domain) {
        (RecordCreateValueSource::Literal { value }, RecordCreateValueDomain::Enum { .. })
            if value.is_string() =>
        {
            Ok(())
        }
        (RecordCreateValueSource::Input { .. }, RecordCreateValueDomain::Enum { values })
            if values.iter().all(Value::is_string) =>
        {
            Ok(())
        }
        _ => Err(format!(
            "{name} must be a string literal or person input bounded by a finite string enum"
        )),
    }
}

fn validate_create_value(
    context: &str,
    declaration: &RecordCreateValue,
    inputs: &BTreeMap<String, InputDecl>,
) -> Result<(), String> {
    validate_create_domain(context, &declaration.domain, inputs, false)?;
    match &declaration.source {
        RecordCreateValueSource::Literal { value } => {
            if declaration.label.is_some() {
                return Err(format!("{context} literal cannot declare a control label"));
            }
            if !create_domain_admits(&declaration.domain, value) {
                return Err(format!("{context} literal is outside its declared domain"));
            }
        }
        RecordCreateValueSource::Input { input } => {
            validate_create_control(context, input, declaration.label.as_deref())?;
            if matches!(
                declaration.domain,
                RecordCreateValueDomain::BoundInput { .. }
            ) {
                return Err(format!(
                    "{context} person input cannot use a bound_input domain"
                ));
            }
        }
        RecordCreateValueSource::BoundInput { slot } => {
            validate_create_control(context, slot, declaration.label.as_deref())?;
            if !matches!(
                declaration.domain,
                RecordCreateValueDomain::BoundInput { .. }
            ) {
                return Err(format!(
                    "{context} bound_input source requires a bound_input domain"
                ));
            }
        }
    }
    Ok(())
}

fn validate_create_control(context: &str, name: &str, label: Option<&str>) -> Result<(), String> {
    if !valid_port(name) {
        return Err(format!(
            "{context} input name '{name}' is not a stable identifier"
        ));
    }
    let Some(label) = label else {
        return Err(format!("{context} person-supplied value declares no label"));
    };
    if label.trim().is_empty()
        || label.len() > MAX_LABEL_BYTES
        || label.chars().any(char::is_control)
    {
        return Err(format!(
            "{context} label is blank, too long, or contains control characters"
        ));
    }
    Ok(())
}

fn validate_create_domain(
    context: &str,
    domain: &RecordCreateValueDomain,
    inputs: &BTreeMap<String, InputDecl>,
    nested: bool,
) -> Result<(), String> {
    match domain {
        RecordCreateValueDomain::Enum { values } => {
            if values.is_empty() || values.len() > MAX_DOMAIN_MEMBERS {
                return Err(format!(
                    "{context} enum width is outside 1..={MAX_DOMAIN_MEMBERS}"
                ));
            }
            if values
                .iter()
                .any(|value| value.is_null() || value.is_array() || value.is_object())
            {
                return Err(format!("{context} enum members must be scalar JSON values"));
            }
            let unique = values
                .iter()
                .map(canonical_json_bytes)
                .collect::<BTreeSet<_>>();
            if unique.len() != values.len() {
                return Err(format!("{context} enum contains duplicate members"));
            }
        }
        RecordCreateValueDomain::String {
            min_length,
            max_length,
        } => {
            if min_length > max_length || *max_length > MAX_CREATE_STRING_LENGTH {
                return Err(format!("{context} string bounds are invalid"));
            }
        }
        RecordCreateValueDomain::Number { min, max, step } => {
            if min.is_some_and(|v| !v.is_finite())
                || max.is_some_and(|v| !v.is_finite())
                || step.is_some_and(|v| !v.is_finite() || v <= 0.0)
                || matches!((min, max), (Some(min), Some(max)) if min > max)
            {
                return Err(format!("{context} number bounds or step are invalid"));
            }
        }
        RecordCreateValueDomain::Date { min, max } => {
            let parse = |value: &String| chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d");
            if min.as_ref().is_some_and(|v| parse(v).is_err())
                || max.as_ref().is_some_and(|v| parse(v).is_err())
                || matches!((min, max), (Some(min), Some(max)) if min > max)
            {
                return Err(format!("{context} date bounds are invalid"));
            }
        }
        RecordCreateValueDomain::Datetime { min, max } => {
            let parse = |value: &String| chrono::DateTime::parse_from_rfc3339(value);
            if min.as_ref().is_some_and(|v| parse(v).is_err())
                || max.as_ref().is_some_and(|v| parse(v).is_err())
                || matches!((min, max), (Some(min), Some(max)) if parse(min).ok() > parse(max).ok())
            {
                return Err(format!("{context} datetime bounds are invalid"));
            }
        }
        RecordCreateValueDomain::BoundInput { port } => {
            require_collection_port(port, inputs, context)?;
        }
        RecordCreateValueDomain::List {
            min_items,
            max_items,
            item,
        } => {
            if nested || min_items > max_items || *max_items > MAX_CREATE_LIST_ITEMS {
                return Err(format!("{context} list bounds are invalid or nested"));
            }
            if matches!(item.as_ref(), RecordCreateValueDomain::BoundInput { .. }) {
                return Err(format!(
                    "{context} bound record lists are not supported initially"
                ));
            }
            validate_create_domain(context, item, inputs, true)?;
        }
        RecordCreateValueDomain::Boolean => {}
    }
    Ok(())
}

fn require_collection_port(
    port: &str,
    inputs: &BTreeMap<String, InputDecl>,
    context: &str,
) -> Result<(), String> {
    let Some(input) = inputs.get(port) else {
        return Err(format!("{context} names undeclared input port '{port}'"));
    };
    if input.envelope != COLLECTION_ENVELOPE {
        return Err(format!("{context} names non-record input port '{port}'"));
    }
    Ok(())
}

fn valid_create_name(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 256 && !value.chars().any(char::is_control)
}

fn create_domain_admits(domain: &RecordCreateValueDomain, value: &Value) -> bool {
    match domain {
        RecordCreateValueDomain::Enum { values } => values.iter().any(|member| {
            match (member, value) {
                // MDX numeric literals enter the manifest through SWC's f64
                // representation, while a browser JSON round trip may encode
                // an integral value without a decimal point. Those are the
                // same JSON-domain number even though serde_json keeps them in
                // different internal variants.
                (Value::Number(member), Value::Number(value)) => member
                    .as_f64()
                    .zip(value.as_f64())
                    .is_some_and(|(member, value)| {
                        member.is_finite() && value.is_finite() && member == value
                    }),
                _ => member == value,
            }
        }),
        RecordCreateValueDomain::String {
            min_length,
            max_length,
        } => value.as_str().is_some_and(|v| {
            let length = v.chars().count();
            (*min_length..=*max_length).contains(&length)
        }),
        RecordCreateValueDomain::Number { min, max, step } => value.as_f64().is_some_and(|v| {
            min.is_none_or(|min| v >= min)
                && max.is_none_or(|max| v <= max)
                && step.is_none_or(|step| {
                    let origin = min.unwrap_or(0.0);
                    ((v - origin) / step - ((v - origin) / step).round()).abs() < 1e-9
                })
        }),
        RecordCreateValueDomain::Boolean => value.is_boolean(),
        RecordCreateValueDomain::Date { min, max } => value.as_str().is_some_and(|v| {
            chrono::NaiveDate::parse_from_str(v, "%Y-%m-%d").is_ok()
                && min.as_deref().is_none_or(|min| v >= min)
                && max.as_deref().is_none_or(|max| v <= max)
        }),
        RecordCreateValueDomain::Datetime { min, max } => value.as_str().is_some_and(|v| {
            let Ok(value) = chrono::DateTime::parse_from_rfc3339(v) else {
                return false;
            };
            min.as_ref().is_none_or(|min| {
                chrono::DateTime::parse_from_rfc3339(min).is_ok_and(|min| value >= min)
            }) && max.as_ref().is_none_or(|max| {
                chrono::DateTime::parse_from_rfc3339(max).is_ok_and(|max| value <= max)
            })
        }),
        RecordCreateValueDomain::BoundInput { .. } => value.as_str().is_some_and(|v| !v.is_empty()),
        RecordCreateValueDomain::List {
            min_items,
            max_items,
            item,
        } => value.as_array().is_some_and(|values| {
            (*min_items..=*max_items).contains(&values.len())
                && values.iter().all(|value| create_domain_admits(item, value))
        }),
    }
}

fn valid_entry_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'.'
        })
}

pub(crate) fn valid_facet_key(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= MAX_FACET_KEY_BYTES
        && !value.chars().any(char::is_control)
}

fn validate_inputs(inputs: &BTreeMap<String, InputDecl>) -> Result<(), mdx::Failure> {
    for (name, input) in inputs {
        if !valid_port(name) || !input_decl_is_supported(input) {
            return Err(mdx::Failure::new(
                "named_input_incompatible",
                "manifest",
                format!("input port '{name}' has an invalid name or envelope"),
            ));
        }
    }
    Ok(())
}

pub fn input_decl_is_supported(input: &InputDecl) -> bool {
    let valid_digest = input.schema_sha256.as_deref().is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    let valid_relations = input.relations.iter().all(|(name, dependency)| {
        valid_port(name)
            && !dependency.identity.is_empty()
            && dependency.identity.len() <= 256
            && !dependency.identity.chars().any(char::is_control)
            && dependency.semantic_version > 0
    });
    match (input.envelope.as_str(), &input.projection) {
        (COLLECTION_ENVELOPE, None) => input.schema_sha256.is_none() && input.relations.is_empty(),
        (RELATION_ENVELOPE, None) => {
            (input.schema_sha256.is_none() && input.relations.is_empty())
                || (valid_digest && valid_relations)
        }
        (
            GROUPED_COUNT_ENVELOPE,
            Some(InputProjection::GroupedCount {
                axis:
                    GroupedCountAxis::RecordField {
                        field: GroupedCountRecordField::Kind,
                    },
            }),
        ) => input.schema_sha256.is_none() && input.relations.is_empty(),
        (
            GROUPED_COUNT_ENVELOPE,
            Some(InputProjection::GroupedCount {
                axis: GroupedCountAxis::Facet { key },
            }),
        ) => input.schema_sha256.is_none() && input.relations.is_empty() && valid_facet_key(key),
        _ => false,
    }
}

fn validate_module_input_maps(
    mappings: &BTreeMap<String, ModuleInputMap>,
    imports: &[ImportRef],
    inputs: &BTreeMap<String, InputDecl>,
) -> Result<(), mdx::Failure> {
    let imports_by_local = imports
        .iter()
        .flat_map(|import| import.names.iter().map(move |name| (&name.local, import)))
        .collect::<BTreeMap<_, _>>();
    for (local, mapping) in mappings {
        let import = imports_by_local.get(local).ok_or_else(|| {
            mdx::Failure::new(
                "module_interface_incompatible",
                "manifest",
                format!("module input mapping '{local}' has no exact import"),
            )
        })?;
        let imported = import
            .names
            .iter()
            .find(|name| name.local == *local)
            .expect("local import indexed");
        if mapping.publication_event_id != import.address.publication_event_id
            || mapping.export != imported.exported
            || mapping
                .ports
                .values()
                .any(|parent| !inputs.contains_key(parent))
            || mapping.ports.keys().any(|child| !valid_port(child))
        {
            return Err(mdx::Failure::new(
                "module_interface_incompatible",
                "manifest",
                format!("module input mapping '{local}' is incompatible"),
            ));
        }
    }
    Ok(())
}

fn validate_capabilities(
    requests: &[CapabilityRequest],
    inputs: &BTreeMap<String, InputDecl>,
    required_capabilities: &BTreeSet<String>,
) -> Result<(), mdx::Failure> {
    let mut seen = BTreeSet::new();
    for request in requests {
        match request.capability.as_str() {
            "input.read" => {
                let scope = request.scope.as_object().filter(|scope| scope.len() == 1);
                let port = scope
                    .and_then(|scope| scope.get("port"))
                    .and_then(Value::as_str)
                    .filter(|port| inputs.contains_key(*port))
                    .ok_or_else(|| {
                        mdx::Failure::new(
                            "module_capability_denied",
                            "manifest",
                            "input.read must name exactly one declared module port",
                        )
                    })?;
                if !seen.insert(format!("{}:{port}", request.capability)) {
                    return Err(descriptor_failure("capability request is duplicated"));
                }
            }
            "navigation.record.user_gesture" | "navigation.external.user_gesture" => {
                if request
                    .scope
                    .as_object()
                    .is_none_or(|scope| !scope.is_empty())
                {
                    return Err(mdx::Failure::new(
                        "module_capability_denied",
                        "manifest",
                        "navigation capability scope must be the exact empty host-policy scope",
                    )
                    .detail("capability", request.capability.clone()));
                }
                if !seen.insert(request.capability.clone()) {
                    return Err(descriptor_failure("capability request is duplicated"));
                }
            }
            _ => {
                return Err(mdx::Failure::new(
                    "module_capability_denied",
                    "manifest",
                    "native.mdx.v2 does not support the requested capability",
                )
                .detail("capability", request.capability.clone()))
            }
        }
    }
    for capability in required_capabilities {
        if !requests
            .iter()
            .any(|request| request.capability == *capability)
        {
            return Err(mdx::Failure::new(
                "module_capability_denied",
                "manifest",
                "source uses a navigation surface without requesting its capability",
            )
            .detail("capability", capability.clone()));
        }
    }
    Ok(())
}

fn valid_port(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_export_name(value: &str) -> Result<(), mdx::Failure> {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(descriptor_failure("module export name is blank"));
    };
    if !(first == '_' || first == '$' || first.is_ascii_alphabetic())
        || !chars.all(|ch| ch == '_' || ch == '$' || ch.is_ascii_alphanumeric())
    {
        return Err(descriptor_failure(format!(
            "module export name '{value}' is invalid"
        )));
    }
    Ok(())
}

/// The name an export clause publishes, whether written as an identifier or as
/// a string literal (`export { x as "nativeStyles" }`).
fn exported_name(name: &ModuleExportName) -> String {
    match name {
        ModuleExportName::Ident(ident) => ident.sym.to_string(),
        ModuleExportName::Str(literal) => literal.value.to_string(),
    }
}

fn descriptor_failure(message: impl Into<String>) -> mdx::Failure {
    mdx::Failure::new("module_descriptor_invalid", "manifest", message)
}

fn authored_offset_range(source: &str, start_offset: usize, end_offset: usize) -> Value {
    fn point(source: &str, offset: usize) -> Value {
        let prefix = &source[..offset];
        let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
        let column = prefix
            .rsplit_once('\n')
            .map_or(prefix, |(_, tail)| tail)
            .chars()
            .count()
            + 1;
        json!({ "line": line, "column": column, "offset": offset })
    }
    json!({
        "start": point(source, start_offset),
        "end": point(source, end_offset),
        "source": "authored_mdx",
    })
}

pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn canonical(value: &Value) -> Value {
        match value {
            Value::Array(values) => Value::Array(values.iter().map(canonical).collect()),
            Value::Object(values) => {
                let mut keys = values.keys().collect::<Vec<_>>();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|key| (key.clone(), canonical(&values[key])))
                        .collect(),
                )
            }
            value => value.clone(),
        }
    }
    serde_json::to_vec(&canonical(value)).expect("canonical JSON serializes")
}

pub fn runtime_edge_key(importer: &str, import: &ImportRef) -> String {
    mdx::sha256_hex(&canonical_json_bytes(&json!({
        "namespace": "native.mdx.runtime-edge.v1",
        "importer": importer,
        "specifier": import.specifier,
        "source_range": import.source_range,
    })))
}

pub fn descriptor() -> Value {
    json!({
      "id": RUNTIME_ID, "contract_version": 2, "adapter_revision": ADAPTER_REVISION,
      "body_media_type": "text/mdx; charset=utf-8", "source_encoding": "utf-8",
      "compiler": { "id": "mdxjs-rs", "crate": "mdxjs", "version": "1.0.4",
        "lock_sha256_required": true, "options_profile": "native.mdx.compile.v2",
        "development": false, "jsx_runtime": "automatic", "jsx_import_source": RUNTIME_ID,
        "provider_import_source": "native.mdx.v2/provider", "plugins": [] },
      "executor": { "id": "rquickjs.quickjs-ng", "crate": "rquickjs", "version": "0.11.0",
        "sys_crate": "rquickjs-sys@0.11.0", "profile": "native.mdx.quickjs.v2",
        "module_loader": "verified-in-memory-native-modules-only-before-content" },
      "source_contracts": { "artifact_manifest": ARTIFACT_SCHEMA, "module_manifest": MODULE_SCHEMA,
        "release_descriptor": RELEASE_SCHEMA, "module_specifier": "native.module-specifier.v1" },
      "component_policy": { "id": mdx::V2_COMPONENT_POLICY_ID,
        "version": mdx::V2_COMPONENT_POLICY_VERSION },
      "input": { "default_envelope": "native.artifact-input.v1", "named_envelope": NAMED_INPUT_ABI,
        "collection_envelope": COLLECTION_ENVELOPE,
        "grouped_count_envelope": GROUPED_COUNT_ENVELOPE,
        "relation_envelope": RELATION_ENVELOPE,
        "artifact_record_schema": ARTIFACT_RECORD_SCHEMA },
      "capabilities": { "model": "native.module-capability-intersection.v1",
        "grant_contract": "native.artifact-module-grant.v1",
        "supported": ["input.read", "navigation.record.user_gesture", "navigation.external.user_gesture"],
        "mutation_supported": false, "live_query_supported": false },
      "execution_profile": "sandboxed-authority-free", "output_surface": "workbench.safe-tree.v1",
      "output_abi": "native.safe-tree.v1", "diagnostic_format": "native.artifact-diagnostic.v1",
      "author_styles": { "scope_root": STYLE_SCOPE_ROOT, "scope_limit": STYLE_SCOPE_LIMIT,
        "scope_limit_role": "host_owned_closed_chrome" },
      "cache_namespace": CACHE_NAMESPACE,
      "limits": { "source_utf8_bytes_each": 524288, "aggregate_source_utf8_bytes": MAX_AGGREGATE_SOURCE,
        "dependency_modules": MAX_MODULES, "dependency_depth": MAX_DEPTH, "dependency_edges": MAX_EDGES,
        "public_exports": MAX_EXPORTS, "compiled_js_bytes": MAX_AGGREGATE_COMPILED,
        "input_records": MAX_INPUT_RECORDS, "input_json_bytes": MAX_INPUT_JSON_BYTES,
        "quickjs_heap_bytes": 67108864,
        "grouped_count_records": MAX_GROUPED_COUNT_RECORDS,
        "grouped_count_buckets": MAX_GROUPED_COUNT_BUCKETS,
        "grouped_count_key_bytes": MAX_GROUPED_COUNT_KEY_BYTES,
        "quickjs_stack_bytes": 524288, "execution_interrupt_ticks": 250000,
        "output_nodes": 10000, "output_depth": 64,
        "output_json_bytes": 2097152, "data_image_decoded_bytes": 262144,
        "stylesheet_source_utf8_bytes": css::MAX_SOURCE_BYTES, "stylesheet_rules": css::MAX_RULES }
    })
}

pub fn rewrite_imports(
    compiled: &str,
    replacements: &[(usize, usize, String)],
) -> Result<String, mdx::Failure> {
    let mut ordered = replacements.to_vec();
    ordered.sort_by_key(|(start, _, _)| std::cmp::Reverse(*start));
    let mut previous_start = compiled.len();
    let mut rewritten = compiled.to_owned();
    for (start, end, replacement) in ordered {
        if start >= end || end > previous_start || end > rewritten.len() {
            return Err(descriptor_failure(
                "compiled import spans overlap or fall outside the verified source",
            ));
        }
        let literal = &rewritten[start..end];
        let quote = literal.as_bytes().first().copied().ok_or_else(|| {
            descriptor_failure("compiled import span does not contain a string literal")
        })?;
        if !matches!(quote, b'\'' | b'"') || literal.as_bytes().last().copied() != Some(quote) {
            return Err(descriptor_failure(
                "compiled import span does not contain an exact string literal",
            ));
        }
        let replacement = format!(
            "{}{}{}",
            quote as char,
            replacement
                .replace('\\', "\\\\")
                .replace(quote as char, &format!("\\{}", quote as char)),
            quote as char
        );
        rewritten.replace_range(start..end, &replacement);
        previous_start = start;
    }
    Ok(rewritten)
}

pub fn instrument_release_module(compiled: String, origin_key: &str) -> String {
    let origin = serde_json::to_string(origin_key).expect("runtime origin key JSON");
    format!(
        "globalThis.__nativeBridge.enterModule({origin});\n{compiled}\nglobalThis.__nativeBridge.exitModule();\n"
    )
}

pub fn edge_wrapper(
    internal_module: &str,
    context_key: &str,
    origin_key: &str,
    edge_key: &str,
    names: &[(ImportName, ExportInterface)],
) -> String {
    let imports = names
        .iter()
        .enumerate()
        .map(|(index, (name, _))| format!("{} as __nativeExport{index}", name.exported))
        .collect::<Vec<_>>()
        .join(",");
    let exports = names
        .iter()
        .enumerate()
        .map(|(index, (name, interface))| {
            let interface_json = serde_json::to_string(interface).expect("export interface JSON");
            let origin = serde_json::to_string(origin_key).expect("runtime origin key");
            let export = serde_json::to_string(&name.exported).expect("runtime export name");
            let edge = serde_json::to_string(edge_key).expect("runtime edge key");
            match interface.kind.as_str() {
                "component" => format!(
                    "export const {}=(props)=>globalThis.__nativeBridge.withOrigin({origin},{export},{edge},()=>globalThis.__nativeBridge.abiComponent(__nativeExport{index},{interface_json},props,__nativeContext));",
                    name.exported
                ),
                "function" => format!(
                    "export const {}=(...args)=>globalThis.__nativeBridge.withOrigin({origin},{export},{edge},()=>globalThis.__nativeBridge.abiFunction(__nativeExport{index},{interface_json},args,__nativeContext));",
                    name.exported
                ),
                "constant" => format!(
                    "export const {}=globalThis.__nativeBridge.withOrigin({origin},{export},{edge},()=>globalThis.__nativeBridge.abiConstant(__nativeExport{index},{interface_json}));",
                    name.exported
                ),
                _ => unreachable!("manifest export kinds are validated"),
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "import {{{imports}}} from {};\nconst __nativeContext=globalThis.__nativeBridge.context({});\n{exports}",
        serde_json::to_string(internal_module).expect("internal module name"),
        serde_json::to_string(context_key).expect("context key"),
    )
}

/// Execute the linked module graph and validate its output into a safe tree.
///
/// Returns what it measured alongside the tree rather than reporting it: this
/// runs inside `spawn_blocking`, where a `RenderTelemetry` cannot be held by
/// reference, so the caller folds the phases back in with
/// `RenderTelemetry::absorb`.
pub fn render_verified(
    root_compiled: &str,
    modules: HashMap<String, String>,
    input: &Value,
    contexts: &Value,
) -> Result<(Value, mdx::ExecutionPhases), mdx::Failure> {
    let mut phases = mdx::ExecutionPhases::default();
    let started = Instant::now();
    let serialized = mdx::execute_v2_graph(root_compiled, modules, input, contexts, &mut phases)?;
    phases.execute_micros = elapsed_micros(started);
    phases.output_json_bytes = serialized.len();
    if serialized.len() > mdx::MAX_OUTPUT_BYTES {
        return Err(mdx::Failure::new(
            "mdx_resource_limit_exceeded",
            "output",
            "safe-tree output exceeds the serialized byte limit",
        )
        .detail("limit", "output_json_bytes")
        .detail("maximum", mdx::MAX_OUTPUT_BYTES as u64));
    }
    let decode_started = Instant::now();
    let mut deserializer = serde_json::Deserializer::from_str(&serialized);
    deserializer.disable_recursion_limit();
    let mut tree = Value::deserialize(&mut deserializer).map_err(|_| {
        mdx::Failure::new(
            "mdx_output_invalid",
            "output",
            "MDX returned a value that is not a serializable safe tree",
        )
    })?;
    deserializer.end().map_err(|_| {
        mdx::Failure::new(
            "mdx_output_invalid",
            "output",
            "MDX returned trailing data after its safe-tree value",
        )
    })?;
    phases.decode_micros = elapsed_micros(decode_started);
    let validate_started = Instant::now();
    phases.output_nodes = mdx::validate_v2_tree_with_contexts(&mut tree, input, contexts)?;
    phases.validate_micros = elapsed_micros(validate_started);
    Ok((tree, phases))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE_ID: &str = "11111111-1111-4111-8111-111111111111";
    const EVENT_ID: &str = "77777777-7777-4777-8777-777777777777";
    const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NO_STYLES_CACHE_KEY: &str =
        "4a6036b30e75629a72816eac6b166beb4fa63fbe301add53a95f251abd78cf36";
    const STYLED_CACHE_KEY: &str =
        "f79177dfc7a7a89de7c7bc494851524cc75c552b7f6970052cda38894daa891b";

    #[test]
    fn descriptor_and_diagnostics_share_the_adapter_revision() {
        assert_eq!(descriptor()["adapter_revision"], ADAPTER_REVISION);
        assert_eq!(descriptor()["cache_namespace"], CACHE_NAMESPACE);
        let failure = normalize_failure(mdx::Failure::new("fixture", "test", "fixture"));
        assert_eq!(failure.details["runtime"], RUNTIME_ID);
        assert_eq!(failure.details["adapter_revision"], ADAPTER_REVISION);
    }

    #[test]
    fn exact_specifier_is_portable_and_closed() {
        let exact = format!("native:module/{MODULE_ID}@event-{EVENT_ID}?sha256={DIGEST}");
        assert_eq!(ModuleAddress::parse(&exact).unwrap().specifier(), exact);
        for invalid in [
            format!("native:module/{MODULE_ID}@{EVENT_ID}?sha256={DIGEST}"),
            format!("native:module/{MODULE_ID}@event-{EVENT_ID}?sha256={DIGEST}&latest=1"),
            format!(
                "native:module/{MODULE_ID}@event-{EVENT_ID}?sha256={}",
                DIGEST.to_uppercase()
            ),
            "./component.mdx".into(),
            "https://example.test/component.mdx".into(),
        ] {
            assert_eq!(
                ModuleAddress::parse(&invalid).unwrap_err().code,
                "module_specifier_invalid"
            );
        }
    }

    #[test]
    fn module_manifest_is_static_and_exports_match() {
        let source = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { value: { kind: "constant", result: { type: "object", properties: { currency: { type: "string", required: true } } }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export const value = { currency: "GBP" }
"#;
        let parsed = parse_module(source).unwrap();
        assert!(parsed.imports.is_empty());

        let computed = source.replace("schema:", "[\"schema\"]:");
        assert_eq!(
            parse_module(&computed).unwrap_err().code,
            "module_descriptor_invalid"
        );
        let duplicate = source.replace(
            "schema: \"native.mdx.module.v1\",",
            "schema: \"native.mdx.module.v1\", schema: \"native.mdx.module.v1\",",
        );
        assert_eq!(
            parse_module(&duplicate).unwrap_err().code,
            "module_descriptor_invalid"
        );

        let unrelated_a = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { probe: { kind: "function", args: [], result: { type: "string" }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export function probe() { const object = { a: "a" }; return String(object.a) }
"#;
        parse_module(unrelated_a).expect("ordinary strings and member names are not navigation");
    }

    #[test]
    fn parsed_cache_hits_and_rebuilds_a_corrupt_entry() {
        let source = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: []
}

<p>cache</p>
"#;
        let partition = "test/v2-cache-corruption";
        assert_eq!(parse_artifact_cached(source, partition).unwrap().1, "miss");
        assert_eq!(parse_artifact_cached(source, partition).unwrap().1, "hit");
        let key = format!(
            "{}:{}:{}:artifact:{}",
            CACHE_NAMESPACE,
            ADAPTER_REVISION,
            mdx::sha256_hex(partition.as_bytes()),
            mdx::sha256_hex(source.as_bytes())
        );
        parsed_cache()
            .lock()
            .unwrap()
            .entries
            .get_mut(&key)
            .unwrap()
            .parsed
            .compiled
            .push_str("corrupt");
        assert_eq!(
            parse_artifact_cached(source, partition).unwrap().1,
            "rebuilt_corrupt"
        );
    }

    #[test]
    fn compiled_graph_cache_hits_and_evicts_corruption() {
        let key = "graph-corruption-key";
        let partition = "test/v2-graph-cache-corruption";
        graph_cache_insert(
            key,
            partition,
            "export default 1".into(),
            HashMap::from([("dependency".into(), "export const value=1".into())]),
        );
        assert!(matches!(
            graph_cache_lookup(key, partition),
            GraphCacheLookup::Hit { .. }
        ));
        let storage_key = format!("{}:{key}", mdx::sha256_hex(partition.as_bytes()));
        compiled_graph_cache()
            .lock()
            .unwrap()
            .entries
            .get_mut(&storage_key)
            .unwrap()
            .modules
            .get_mut("dependency")
            .unwrap()
            .push_str("// corrupt");
        assert!(matches!(
            graph_cache_lookup(key, partition),
            GraphCacheLookup::Corrupt
        ));
        assert!(matches!(
            graph_cache_lookup(key, partition),
            GraphCacheLookup::Miss
        ));
    }

    #[test]
    fn import_rewrite_uses_verified_spans_not_first_occurrence_search() {
        let compiled = "// \"same\" must stay\nimport { X as A } from \"same\";\nconst note = \"same\";\nimport { X as B } from \"same\";";
        let first = compiled.find("from \"same\"").unwrap() + "from ".len();
        let second = compiled.rfind("from \"same\"").unwrap() + "from ".len();
        let rewritten = rewrite_imports(
            compiled,
            &[
                (first, first + "\"same\"".len(), "wrapper-a".into()),
                (second, second + "\"same\"".len(), "wrapper-b".into()),
            ],
        )
        .unwrap();
        assert!(rewritten.starts_with("// \"same\" must stay"));
        assert!(rewritten.contains("const note = \"same\""));
        assert_eq!(rewritten.matches("wrapper-a").count(), 1);
        assert_eq!(rewritten.matches("wrapper-b").count(), 1);
    }

    #[test]
    fn duplicate_multiline_imports_keep_distinct_authored_mdx_ranges() {
        let exact = format!("native:module/{MODULE_ID}@event-{EVENT_ID}?sha256={DIGEST}");
        let source = format!(
            r#"import {{
  X as A
}} from "{exact}"
import {{ X as B }} from "{exact}"
export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: []
}}

<><A /><B /></>
"#
        );
        let parsed = parse_artifact(&source).expect("duplicate exact imports parse");
        assert_eq!(parsed.imports.len(), 2);
        let first = &parsed.imports[0].source_range;
        let second = &parsed.imports[1].source_range;
        assert_eq!(first["source"], "authored_mdx");
        assert_eq!(first["start"]["line"], 1);
        assert_eq!(first["end"]["line"], 3);
        assert_eq!(second["start"]["line"], 4);
        assert_ne!(first["start"]["offset"], second["start"]["offset"]);
    }

    // -- tier-one author CSS -------------------------------------------------

    fn read_only_source(extra: &str, body: &str) -> String {
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2", inputs: {{}}, module_inputs: {{}}, capability_requests: []
}}
{extra}

{body}
"#
        )
    }

    /// These helpers assert on the tree; the phases alongside it are the
    /// caller's to report, and every one of these tests is that caller.
    fn render_read_only_v2(source: &str) -> Result<Value, mdx::Failure> {
        let parsed = parse_artifact(source)?;
        render_verified(
            &parsed.compiled,
            HashMap::new(),
            &json!({ "version": NAMED_INPUT_ABI, "mode": "named", "inputs": {}, "records": [] }),
            &json!({ "$root": { "inputs": {} } }),
        )
        .map(|(tree, _)| tree)
    }

    #[test]
    fn author_styles_are_validated_prefixed_and_scoped_at_parse_time() {
        let source = read_only_source(
            r#"export const nativeStyles = ".card { color: red; }""#,
            "<p>styled</p>",
        );
        let parsed = parse_artifact(&source).expect("author styles validate at parse time");
        let styles = parsed
            .styles
            .as_ref()
            .expect("stylesheet reaches the caller");
        assert_eq!(
            styles.css,
            format!(
                "@scope ({STYLE_SCOPE_ROOT}) to ({STYLE_SCOPE_LIMIT}) {{\n  .{}card {{\n    color: red;\n  }}\n}}\n",
                mdx::AUTHOR_CLASS_PREFIX
            )
        );
        assert_eq!(parsed.styles_sha256(), Some(styles.sha256.as_str()));
        // The prefix is what stops an author class from resolving to a host
        // one, so it must not itself be able to spell a host class.
        assert!(!mdx::AUTHOR_CLASS_PREFIX.starts_with("safe"));
        assert!(!format!("{}safe-callout", mdx::AUTHOR_CLASS_PREFIX).starts_with("safe-"));

        // An artifact that declares no styles carries none, and is otherwise
        // exactly the artifact it was before this export existed.
        let plain = parse_artifact(&read_only_source("", "<p>plain</p>")).expect("plain artifact");
        assert!(plain.styles.is_none());
        assert_eq!(plain.styles_sha256(), None);

        // A rejection keeps the CSS validator's named rule and code, under
        // this adapter's runtime identity.
        let rejected = parse_artifact(&read_only_source(
            r#"export const nativeStyles = "@import url('https://example.test/a.css');""#,
            "<p>x</p>",
        ))
        .expect_err("@import is refused");
        assert_eq!(rejected.code, "css_policy_violation");
        assert_eq!(rejected.details["rule"], "forbidden_import");
        assert_eq!(rejected.details["runtime"], RUNTIME_ID);
        assert_eq!(rejected.details["adapter_revision"], ADAPTER_REVISION);
        assert_eq!(rejected.details["css_runtime"], css::RUNTIME_ID);

        // A module cannot declare author CSS: it has no scope root of its own.
        let module = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { value: { kind: "constant", result: { type: "string" }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export const value = "v"
export const nativeStyles = ".card { color: red }"
"#;
        assert_eq!(
            parse_module(module).expect_err("modules cannot style").code,
            "module_descriptor_invalid"
        );
    }

    /// Tier two: a *writable* artifact may carry author CSS.
    ///
    /// Tier one refused this pair outright with `rule: styles_require_read_only`.
    /// That gate is gone, and this test is the one that would have caught its
    /// silent return. The property retained for remaining host controls — an
    /// author rule cannot match and rewrite them — is carried by the scope
    /// limit, which `the_scope_limit_names_the_host_interactive_marker` pins.
    #[test]
    fn declared_styles_over_a_writable_artifact_are_accepted() {
        let styled = |source: String| {
            source.replace(
                "\n\n<Metric",
                "\nexport const nativeStyles = \".card { color: red }\"\n\n<Metric",
            )
        };
        parse_artifact(&styled(interaction_artifact("")))
            .expect("styles over a read-only artifact stay legal");
        parse_artifact(&interaction_artifact(TRIAGE_ENTRY))
            .expect("interactions without styles stay legal");

        let writable = parse_artifact(&styled(interaction_artifact(TRIAGE_ENTRY)))
            .expect("a writable artifact may declare nativeStyles under tier two");
        let styles = writable
            .styles
            .as_ref()
            .expect("the stylesheet reaches the caller");
        assert_eq!(
            styles.css,
            format!(
                "@scope ({STYLE_SCOPE_ROOT}) to ({STYLE_SCOPE_LIMIT}) {{\n  .{}card {{\n    color: red;\n  }}\n}}\n",
                mdx::AUTHOR_CLASS_PREFIX
            )
        );
        assert_eq!(writable.styles_sha256(), Some(styles.sha256.as_str()));

        // The *module* refusal is the gate that stayed: a module has no scope
        // root of its own, so its stylesheet would silently do nothing.
        let module = r#"export const nativeModule = {
  schema: "native.mdx.module.v1", inputs: {},
  exports: { value: { kind: "constant", result: { type: "string" }, uses_inputs: [] } },
  module_inputs: {}, capability_requests: []
}
export const value = "v"
export const nativeStyles = ".card { color: red }"
"#;
        assert_eq!(
            parse_module(module)
                .expect_err("a module still cannot declare author CSS")
                .code,
            "module_descriptor_invalid"
        );
    }

    /// The emitted wrapper names the host's interactive-chrome marker.
    ///
    /// What makes control protection real is a CSS semantic this crate cannot
    /// execute: `@scope (root) to (limit)` excludes the **limit element
    /// itself**, not merely its descendants. A red team confirmed it in a
    /// browser — `.native-interactive::after { content: "Done" }` computes to
    /// `content: "none"`, and `!important` makes no difference, because the
    /// rule never matches rather than losing a cascade. There is no CSS engine
    /// in this crate, so that half is browser-verified and cited in the
    /// `STYLE_SCOPE_LIMIT` doc; a regression in it would be a browser change,
    /// not a change here.
    ///
    /// What *is* checkable in Rust is the half that can regress here: the
    /// marker has to appear as the `to (...)` limit of the generated wrapper,
    /// on a writable artifact as much as a read-only one. If someone folds it
    /// into the root, drops the `to` clause, or moves the marker off the
    /// controls, the emitted text stops saying this.
    #[test]
    fn the_scope_limit_names_the_host_interactive_marker() {
        assert_eq!(STYLE_SCOPE_LIMIT, ".native-interactive");
        // Not an ancestor of the scope root, which is what made tier one's
        // `.safe-tree-host` inert.
        assert_ne!(STYLE_SCOPE_LIMIT, STYLE_SCOPE_ROOT);

        let parsed = parse_artifact(&read_only_source(
            r#"export const nativeStyles = ".card { color: red; }""#,
            "<p>styled</p>",
        ))
        .expect("author styles validate at parse time");
        let css = &parsed.styles.as_ref().expect("stylesheet").css;
        assert!(
            css.starts_with("@scope (.safe-tree) to (.native-interactive) {"),
            "emitted wrapper must name the marker as its limit: {css}"
        );
        // The marker is spelled once, as the limit, and nowhere else.
        assert_eq!(css.matches(".native-interactive").count(), 1);
    }

    #[test]
    fn native_styles_takes_a_substitution_free_template_literal_only() {
        let parsed = parse_artifact(&read_only_source(
            "export const nativeStyles = `\n.card {\n  color: red;\n}\n`",
            "<p>x</p>",
        ))
        .expect("a substitution-free template literal is a static string");
        assert!(parsed
            .styles
            .as_ref()
            .expect("stylesheet")
            .css
            .contains(&format!(".{}card", mdx::AUTHOR_CLASS_PREFIX)));

        // A substitution is not static: its value would need evaluating, and
        // nothing in this model evaluates a declaration.
        let failure = parse_artifact(&read_only_source(
            "export const nativeStyles = `.card { color: ${\"red\"} }`",
            "<p>x</p>",
        ))
        .expect_err("a substitution is refused");
        assert_eq!(failure.code, "module_descriptor_invalid");
        assert!(
            failure.message.contains("no substitutions"),
            "{}",
            failure.message
        );

        // The same arm serves the manifest, which is the reason it is in
        // `static_json` rather than in the styles branch alone.
        parse_artifact(
            r#"export const nativeArtifact = {
  schema: `native.mdx.artifact.v2`, inputs: {}, module_inputs: {}, capability_requests: []
}

<p>x</p>
"#,
        )
        .expect("a template literal is a static manifest string");
    }

    #[test]
    fn author_class_is_admitted_and_prefixed_while_style_and_class_name_stay_denied() {
        let tree = render_read_only_v2(&read_only_source(
            r#"export const nativeStyles = ".card { color: red }""#,
            r#"<p class="card intro">styled</p>"#,
        ))
        .expect("an author class renders");
        let prefix = mdx::AUTHOR_CLASS_PREFIX;
        assert_eq!(
            tree["props"]["class"],
            json!(format!("{prefix}card {prefix}intro"))
        );

        for denied in [
            r#"<p style="color: red">x</p>"#,
            r#"<p className="card">x</p>"#,
            r#"<p id="card">x</p>"#,
        ] {
            render_read_only_v2(&read_only_source("", denied))
                .expect_err("style, className and id stay denied");
        }

        // The accepted class grammar is the class-selector grammar `css.rs`
        // tokenizes, so a name unwritable there is unwritable here.
        let failure = render_read_only_v2(&read_only_source("", r#"<p class="a.b">x</p>"#))
            .expect_err("a class name that is not an identifier is refused");
        assert_eq!(failure.details["rule"], "author_class_grammar");

        // A native component takes the same prop on the same terms.
        let native = render_read_only_v2(&read_only_source(
            "",
            r#"<Stack gap={2} class="row">text</Stack>"#,
        ))
        .expect("native components take an author class too");
        assert_eq!(native["props"]["class"], json!(format!("{prefix}row")));

        // `Fragment` is an intrinsic, so it was admitted and prefixed like any
        // other — and then rendered no element, so the browser dropped the
        // attribute and the author's rule silently never matched. Validation is
        // the only layer that can say so.
        let fragment = render_read_only_v2(&read_only_source(
            "",
            r#"<Fragment class="card"><p>x</p></Fragment>"#,
        ))
        .expect_err("class on Fragment is refused rather than silently dropped");
        assert_eq!(fragment.details["rule"], "class_on_fragment");
        assert_eq!(fragment.details["component"], "Fragment");
    }

    #[test]
    fn compiled_cache_key_omits_the_styles_field_when_there_are_none() {
        let without = compiled_cache_key("body", "manifest", "closure", "lock", None);
        let with = compiled_cache_key("body", "manifest", "closure", "lock", Some("styles"));
        assert_ne!(without, with);
        // Golden, not derived: a no-styles artifact must hash exactly the
        // field list it hashed before author CSS existed. Update this only
        // together with a deliberate `ADAPTER_REVISION` bump — which is what
        // makes changing the key list safe in the first place. Last moved when
        // record.create moved the revision from 11 to 12.
        assert_eq!(without, NO_STYLES_CACHE_KEY);
    }

    /// The field *order* is part of the key, and nothing else pins it.
    ///
    /// `styles_sha256` is appended after `adapter_revision`. Moving it — or
    /// inserting any field ahead of it — changes every styled artifact's key
    /// while the no-styles golden above stays green, so a reordering would
    /// silently invalidate or, worse, silently reuse compiled graphs with the
    /// whole suite passing. Update this only with a deliberate
    /// `ADAPTER_REVISION` bump.
    #[test]
    fn compiled_cache_key_pins_the_field_order_for_a_styled_artifact() {
        assert_eq!(
            compiled_cache_key("body", "manifest", "closure", "lock", Some("styles")),
            STYLED_CACHE_KEY
        );
    }

    /// Flags are the reason `mdx.rs` gives for not rewriting author id
    /// selectors, so they have to be readable outside `css.rs`. `.flags` is
    /// public on the sheet; this is the JSON the render path puts in
    /// `plan.styles.flags`, which is where a person can actually see them.
    #[test]
    fn stylesheet_flags_are_observable_outside_the_css_validator() {
        let parsed = parse_artifact(&read_only_source(
            r#"export const nativeStyles = "@wobble { .card { color: red } } #panel { color: blue }""#,
            "<p>x</p>",
        ))
        .expect("an unknown at-rule and an id selector are flagged, not rejected");
        assert_eq!(
            parsed.styles_flags(),
            vec![
                json!({ "rule": "id_selector", "name": "panel" }),
                json!({ "rule": "unknown_at_rule", "name": "wobble" }),
            ]
        );
        // The id selector reached the emitted sheet unrewritten — which is
        // exactly what the flag is reporting, and is only sound while no
        // element an author can emit carries an author id.
        assert!(parsed.styles.as_ref().unwrap().css.contains("#panel"));
        // An artifact with nothing novel in it says so with an empty list
        // rather than with silence.
        let plain = parse_artifact(&read_only_source(
            r#"export const nativeStyles = ".card { color: red }""#,
            "<p>x</p>",
        ))
        .expect("plain sheet");
        assert!(plain.styles_flags().is_empty());
        assert!(parse_artifact(&read_only_source("", "<p>x</p>"))
            .expect("no sheet")
            .styles_flags()
            .is_empty());
    }

    /// Only `export const nativeStyles = "..."` is read, so every other way of
    /// exporting that name has to be an error. An export clause used to be
    /// ignored: an unstyled artifact and no diagnostic anywhere, while
    /// declaring the export twice was rejected outright. (A bare `const`
    /// followed by an export clause is not expressible at all — MDX admits
    /// only `import`/`export` statements in an ESM block — so the reachable
    /// spellings are the alias and the re-export.)
    #[test]
    fn unsupported_native_styles_export_forms_are_named_rather_than_ignored() {
        for source in [
            "export const sheet = \".card { color: red }\"\nexport { sheet as nativeStyles }",
            "export { nativeStyles } from \"native.module.v1/x\"",
        ] {
            let failure = parse_artifact(&read_only_source(source, "<p>x</p>"))
                .expect_err("an export clause is not a declaration");
            assert_eq!(
                failure.code, "module_descriptor_invalid",
                "{source} -> {failure:?}"
            );
            assert_eq!(
                failure.details["rule"], "styles_export_declaration",
                "{source}"
            );
        }
        // Exporting anything else by clause is untouched: this rule is about
        // one name, not about export syntax.
        parse_artifact(&read_only_source(
            "export const other = 1\nexport { other as alias }",
            "<p>x</p>",
        ))
        .expect("an unrelated export clause is still legal");
    }

    #[test]
    fn descriptor_publishes_the_stylesheet_limits() {
        let descriptor = descriptor();
        assert_eq!(
            descriptor["limits"]["stylesheet_source_utf8_bytes"],
            css::MAX_SOURCE_BYTES
        );
        assert_eq!(descriptor["limits"]["stylesheet_rules"], css::MAX_RULES);
    }

    fn interaction_artifact(entries: &str) -> String {
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "orders" }} }}],
  interactions: [{entries}]
}}

<Metric label="Total" value={{1}} />
"#
        )
    }

    fn grouped_count_source(interactions: &str) -> String {
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ summary: {{
    envelope: "native.grouped-count-envelope.v1", required: true, expose_to_root: true,
    projection: {{ kind: "grouped_count", axis: {{ kind: "record_field", field: "kind" }} }}
  }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "summary" }} }}],
  interactions: [{interactions}]
}}

<Metric label="Total" value={{native.inputs.summary.total}} />
"#
        )
    }

    fn facet_grouped_count_source(key: &str) -> String {
        grouped_count_source("").replace(
            "axis: { kind: \"record_field\", field: \"kind\" }",
            &format!("axis: {{ kind: \"facet\", key: {key} }}"),
        )
    }

    fn relation_source(interactions: &str) -> String {
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ rows: {{ envelope: "native.relation-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [
    {{ capability: "input.read", scope: {{ port: "rows" }} }},
    {{ capability: "navigation.record.user_gesture", scope: {{}} }}
  ],
  interactions: [{interactions}]
}}

<RecordTable records={{native.inputs.rows.relation.rows}} columns={{["name"]}} />
"#
        )
    }

    #[test]
    fn relation_input_is_fixed_projection_free_and_cacheable() {
        let source = relation_source("");
        let parsed = parse_artifact(&source).expect("the fixed relation declaration is supported");
        let Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("artifact parser returns an artifact manifest")
        };
        assert_eq!(manifest.inputs["rows"].envelope, RELATION_ENVELOPE);
        assert_eq!(manifest.inputs["rows"].projection, None);
        assert!(
            manifest.inputs["rows"].relations.is_empty(),
            "pre-pin relation manifests remain valid and unpinned"
        );

        let pinned = source.replace(
            "required: true, expose_to_root: true",
            &format!(
                "required: true, expose_to_root: true, schema_sha256: \"{}\", relations: {{ records: {{ identity: \"native.query-sql.records\", semantic_version: 1 }} }}",
                "a".repeat(64)
            ),
        );
        let pinned = parse_artifact(&pinned).expect("exact semantic relation pins are supported");
        let Manifest::Artifact(pinned) = pinned.manifest else {
            unreachable!("artifact parser returns an artifact manifest")
        };
        assert_eq!(
            pinned.inputs["rows"].relations["records"],
            SemanticRelationDependency {
                identity: "native.query-sql.records".into(),
                semantic_version: 1,
            }
        );
        assert!(parse_artifact(&source.replace(
            "required: true, expose_to_root: true",
            "required: true, expose_to_root: true, relations: { records: { identity: \"native.query-sql.records\", semantic_version: 1 } }",
        ))
        .is_err());

        let (cold, cold_state) = parse_artifact_cached(&source, "relation-cache-test")
            .expect("relation source cold-compiles");
        let (hydrated, hydrated_state) = parse_artifact_cached(&source, "relation-cache-test")
            .expect("relation source hydrates from cache");
        assert_eq!(cold_state, "miss");
        assert_eq!(hydrated_state, "hit");
        assert_eq!(cold.manifest, hydrated.manifest);

        for incompatible in [
            source.replace(
                "required: true, expose_to_root: true",
                "required: true, expose_to_root: true, projection: { kind: \"record_relation\" }",
            ),
            source.replace(
                "required: true, expose_to_root: true",
                "required: true, expose_to_root: true, fields: [\"name\"]",
            ),
        ] {
            assert!(
                parse_artifact(&incompatible).is_err(),
                "relation inputs have no author-defined projection surface"
            );
        }
    }

    #[test]
    fn grouped_count_input_is_typed_and_requires_its_exact_projection() {
        assert_eq!(
            serde_json::to_vec(&GroupedCountAxis::RecordField {
                field: GroupedCountRecordField::Kind,
            })
            .expect("legacy grouped-count axis serializes"),
            br#"{"kind":"record_field","field":"kind"}"#,
            "the shipped record_field:kind bytes are unchanged"
        );
        let parsed = parse_artifact(&grouped_count_source(""))
            .expect("the exact grouped-count declaration is supported");
        let Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("artifact parser returns an artifact manifest")
        };
        assert_eq!(manifest.inputs["summary"].envelope, GROUPED_COUNT_ENVELOPE);

        for (incompatible, expected_code) in [
            (
                grouped_count_source("").replace(
                ",\n    projection: { kind: \"grouped_count\", axis: { kind: \"record_field\", field: \"kind\" } }",
                "",
                ),
                "named_input_incompatible",
            ),
            (
                grouped_count_source("").replace("field: \"kind\"", "field: \"type\""),
                "module_descriptor_invalid",
            ),
        ] {
            let failure = parse_artifact(&incompatible)
                .expect_err("a grouped-count envelope has one exact projection contract");
            assert_eq!(failure.code, expected_code);
        }
    }

    #[test]
    fn facet_grouped_count_axis_is_closed_and_uses_the_facet_key_contract() {
        let source = facet_grouped_count_source("\"status\"");
        let parsed = parse_artifact(&source)
            .expect("a canonical facet grouped-count declaration is supported");
        let Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("artifact parser returns an artifact manifest")
        };
        assert_eq!(
            manifest.inputs["summary"].projection,
            Some(InputProjection::GroupedCount {
                axis: GroupedCountAxis::Facet {
                    key: "status".into(),
                },
            })
        );

        let (cold, cold_state) = parse_artifact_cached(&source, "facet-axis-cache-test")
            .expect("the facet declaration cold-compiles through the source cache");
        let (hydrated, hydrated_state) = parse_artifact_cached(&source, "facet-axis-cache-test")
            .expect("the facet declaration hydrates from the source cache");
        assert_eq!(cold_state, "miss");
        assert_eq!(hydrated_state, "hit");
        assert_eq!(cold.manifest, hydrated.manifest);

        for invalid_key in [
            "\"\"".to_string(),
            "\"   \"".to_string(),
            "\"bad\\u0000key\"".to_string(),
            format!("\"{}\"", "x".repeat(MAX_FACET_KEY_BYTES + 1)),
        ] {
            let failure = parse_artifact(&facet_grouped_count_source(&invalid_key))
                .expect_err("invalid facet keys fail manifest admission");
            assert_eq!(failure.code, "named_input_incompatible");
        }

        for incompatible in [
            facet_grouped_count_source("\"status\"")
                .replace("key: \"status\"", "key: \"status\", field: \"kind\""),
            facet_grouped_count_source("\"status\"").replace("key: \"status\"", ""),
            facet_grouped_count_source("\"status\"").replace("kind: \"facet\"", "kind: \"path\""),
        ] {
            assert_eq!(
                parse_artifact(&incompatible)
                    .expect_err("unknown facet axis shapes fail closed")
                    .code,
                "module_descriptor_invalid"
            );
        }
    }

    #[test]
    fn grouped_count_input_cannot_supply_a_record_interaction_slot() {
        let entry = r#"{
          id: "set_triage", label: "Set triage", effect: "facet.set",
          slots: { record: { domain: { kind: "bound_input", port: "summary" } } },
          facet: "triage", value: { from: "literal", value: "triaged" }
        }"#;
        let failure = parse_artifact(&grouped_count_source(entry))
            .expect_err("aggregate input is not a record authority");
        assert_eq!(failure.code, "interaction_entry_invalid");
        assert!(failure.message.contains("non-record input port 'summary'"));
    }

    #[test]
    fn relation_input_cannot_supply_a_record_interaction_slot() {
        let entry = r#"{
          id: "set_triage", label: "Set triage", effect: "facet.set",
          slots: { record: { domain: { kind: "bound_input", port: "rows" } } },
          facet: "triage", value: { from: "literal", value: "triaged" }
        }"#;
        let failure = parse_artifact(&relation_source(entry))
            .expect_err("relations are read-only record authority");
        assert_eq!(failure.code, "interaction_entry_invalid");
        assert!(failure.message.contains("non-record input port 'rows'"));
    }

    const TRIAGE_ENTRY: &str = r#"{
    id: "mark_triaged", label: "Mark triaged", effect: "facet.set",
    slots: { record: { domain: { kind: "bound_input", port: "orders" } } },
    facet: "triage", value: { from: "literal", value: "triaged" }
  }"#;

    const CREATE_ENTRY: &str = r#"{
    id: "create_task", label: "Create task", effect: "record.create",
    create: {
      destination: { from: "bound_input", port: "orders" },
      shape: {
        type: { source: { from: "literal", value: "WorkItem" }, domain: { kind: "enum", values: ["WorkItem"] } },
        kind: { source: { from: "literal", value: "task" }, domain: { kind: "enum", values: ["task"] } },
        fields: {
          name: { label: "Title", source: { from: "input", input: "name" }, domain: { kind: "string", min_length: 1, max_length: 200 } }
        },
        facets: {
          stream: { label: "Stream", source: { from: "input", input: "stream" }, domain: { kind: "enum", values: ["product", "engineering"] } },
          related: { label: "Related", source: { from: "bound_input", slot: "related" }, domain: { kind: "bound_input", port: "orders" } },
          scores: { label: "Scores", source: { from: "input", input: "scores" }, domain: { kind: "list", min_items: 1, max_items: 3, item: { kind: "number", min: 0, max: 10, step: 1 } } }
        }
      }
    }
  }"#;

    #[test]
    fn record_create_manifest_declares_bounded_general_creation() {
        let parsed = parse_artifact(&interaction_artifact(CREATE_ENTRY))
            .expect("bounded record.create compiles");
        let Manifest::Artifact(manifest) = parsed.manifest else {
            unreachable!("artifact source yields artifact manifest")
        };
        let entry = manifest.interaction("create_task").unwrap();
        assert_eq!(entry.effect, InteractionEffect::RecordCreate);
        let create = entry.create.as_ref().unwrap();
        assert!(matches!(
            &create.destination,
            RecordCreateDestination::BoundInput { port } if port == "orders"
        ));
        assert!(matches!(
            create.shape.fields["name"].domain,
            RecordCreateValueDomain::String {
                min_length: 1,
                max_length: 200
            }
        ));
        assert!(matches!(
            create.shape.facets["related"].source,
            RecordCreateValueSource::BoundInput { ref slot } if slot == "related"
        ));
        assert!(create_domain_admits(
            &create.shape.facets["scores"].domain,
            &json!([0, 5, 10])
        ));
        assert!(!create_domain_admits(
            &create.shape.facets["scores"].domain,
            &json!([0, 5, 11])
        ));
    }

    #[test]
    fn record_create_manifest_fails_closed_on_ports_bounds_sources_and_fields() {
        for (entry, expected) in [
            (CREATE_ENTRY.replace("port: \"orders\" },\n      shape", "port: \"absent\" },\n      shape"), "undeclared input port 'absent'"),
            (CREATE_ENTRY.replace("min_length: 1, max_length: 200", "min_length: 201, max_length: 200"), "string bounds are invalid"),
            (CREATE_ENTRY.replace("max_items: 3", "max_items: 65"), "list bounds are invalid"),
            (CREATE_ENTRY.replace("source: { from: \"bound_input\", slot: \"related\" }, domain: { kind: \"bound_input\", port: \"orders\" }", "source: { from: \"bound_input\", slot: \"related\" }, domain: { kind: \"string\", max_length: 20 }"), "bound_input source requires a bound_input domain"),
            (CREATE_ENTRY.replace("name: { label: \"Title\"", "owner_id: { label: \"Title\""), "not an ordinary record creation field"),
            (CREATE_ENTRY.replace("stream: { label", "lifecycle: { label"), "engine-reserved or spine-owned"),
            (CREATE_ENTRY.replace("input: \"stream\"", "input: \"name\""), "reuses invocation input 'name'"),
            (CREATE_ENTRY.replace("domain: { kind: \"string\", min_length: 1, max_length: 200 }", "domain: { kind: \"boolean\" }"), "field 'name' must resolve to a string"),
        ] {
            let failure = parse_artifact(&interaction_artifact(&entry))
                .expect_err("invalid creation declaration is refused");
            assert_eq!(failure.code, "interaction_entry_invalid");
            assert!(failure.message.contains(expected), "{}: {}", expected, failure.message);
        }
        let unknown = interaction_artifact(&CREATE_ENTRY.replace(
            "destination: { from: \"bound_input\", port: \"orders\" }",
            "destination: { from: \"bound_input\", port: \"orders\", query: \"all\" }",
        ));
        assert_eq!(
            parse_artifact(&unknown).unwrap_err().code,
            "module_descriptor_invalid"
        );
    }

    #[test]
    fn record_create_domains_enforce_scalar_temporal_and_list_bounds() {
        let boolean = RecordCreateValueDomain::Boolean;
        assert!(boolean.admits(&json!(true)));
        assert!(!boolean.admits(&json!("true")));

        let date = RecordCreateValueDomain::Date {
            min: Some("2026-09-01".into()),
            max: Some("2026-09-30".into()),
        };
        assert!(date.admits(&json!("2026-09-02")));
        assert!(!date.admits(&json!("2026-10-01")));

        let datetime = RecordCreateValueDomain::Datetime {
            min: Some("2026-09-02T00:00:00Z".into()),
            max: Some("2026-09-02T23:59:59Z".into()),
        };
        assert!(datetime.admits(&json!("2026-09-02T12:00:00Z")));
        assert!(!datetime.admits(&json!("not-a-datetime")));

        let list = RecordCreateValueDomain::List {
            min_items: 1,
            max_items: 2,
            item: Box::new(RecordCreateValueDomain::String {
                min_length: 1,
                max_length: 3,
            }),
        };
        assert!(list.admits(&json!(["a", "abc"])));
        assert!(!list.admits(&json!([])));
        assert!(!list.admits(&json!(["long"])));
    }

    #[test]
    fn record_create_enum_admits_equivalent_json_number_encodings_only() {
        let authored_float = Value::Number(
            serde_json::Number::from_f64(1.0).expect("finite authored manifest number"),
        );
        let domain = RecordCreateValueDomain::Enum {
            values: vec![authored_float],
        };

        assert!(domain.admits(&json!(1)));
        assert!(domain.admits(&json!(1.0)));
        assert!(!domain.admits(&json!(2)));
        assert!(!domain.admits(&json!("1")));
        assert!(!domain.admits(&json!(true)));
    }

    #[test]
    fn declared_interaction_entries_compile_and_carry_both_domain_widths() {
        let wide = r#"{
    id: "set_triage", label: "Set triage", effect: "facet.set",
    slots: {
      record: { domain: { kind: "bound_input" } },
      choice: { domain: { kind: "values", values: ["triaged", "untriaged", "blocked"] } }
    },
    facet: "triage", value: { from: "slot", slot: "choice" }
  }"#;
        let source = interaction_artifact(&format!("{TRIAGE_ENTRY}, {wide}"));
        let parsed = parse_artifact(&source).expect("declared interaction entries compile");
        let Manifest::Artifact(manifest) = &parsed.manifest else {
            unreachable!("artifact source yields an artifact manifest");
        };
        assert_eq!(manifest.interactions.len(), 2);
        let literal = manifest.interaction("mark_triaged").expect("entry by id");
        assert_eq!(literal.effect, InteractionEffect::FacetSet);
        assert_eq!(literal.facet, "triage");
        // A literal IS a domain, at width one: the same membership mechanism
        // answers for it and for the enumerated slot.
        let literal_domain = literal.value.as_ref().unwrap().domain(literal).unwrap();
        assert!(literal_domain.admits(&json!("triaged")));
        assert!(!literal_domain.admits(&json!("blocked")));
        assert_eq!(literal_domain.sole_member(), Some(&json!("triaged")));
        let wide_entry = manifest.interaction("set_triage").expect("entry by id");
        let wide_domain = wide_entry
            .value
            .as_ref()
            .unwrap()
            .domain(wide_entry)
            .unwrap();
        assert!(wide_domain.admits(&json!("blocked")));
        assert!(!wide_domain.admits(&json!("elsewhere")));
        assert_eq!(wide_domain.sole_member(), None);
        assert!(manifest.interaction("absent").is_none());
    }

    fn interactive_source(body: &str) -> String {
        format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ orders: {{ envelope: "native.collection-envelope.v1", required: true, expose_to_root: true }} }},
  module_inputs: {{}},
  capability_requests: [
    {{ capability: "input.read", scope: {{ port: "orders" }} }},
    {{ capability: "navigation.record.user_gesture", scope: {{}} }}
  ],
  interactions: [{TRIAGE_ENTRY}]
}}

{body}
"#
        )
    }

    #[test]
    fn record_create_is_a_closed_v2_safe_tree_primitive() {
        let source = interactive_source(r#"<RecordCreate entry="create_task" />"#)
            .replace(TRIAGE_ENTRY, CREATE_ENTRY);
        let parsed = parse_artifact(&source).expect("RecordCreate source compiles");
        let (tree, _) = render_verified(
            &parsed.compiled,
            HashMap::new(),
            &interactive_input(),
            &json!({ "$root": { "inputs": {} } }),
        )
        .expect("RecordCreate renders through the v2 policy");
        assert_eq!(tree["type"], "RecordCreate");
        assert_eq!(tree["props"], json!({ "entry": "create_task" }));
        assert_eq!(tree["children"], json!([]));

        for body in [
            r#"<RecordCreate entry="create_task"><span>forged</span></RecordCreate>"#,
            r#"<RecordCreate entry="create_task" class="forged" />"#,
            r#"<RecordCreate entry="create_task" label="forged" />"#,
        ] {
            let source = interactive_source(body).replace(TRIAGE_ENTRY, CREATE_ENTRY);
            let parsed = parse_artifact(&source).expect("shape reaches output validation");
            assert!(render_verified(
                &parsed.compiled,
                HashMap::new(),
                &interactive_input(),
                &json!({ "$root": { "inputs": {} } }),
            )
            .is_err());
        }
    }

    fn interactive_input() -> Value {
        json!({
            "version": NAMED_INPUT_ABI,
            "mode": "named",
            "inputs": {},
            "records": [{
                "id": "record-1", "type": "WorkItem", "kind": "task", "name": "One",
                "summary": null, "lifecycle": "active", "maturity": null,
                "persistence": "enduring", "facets": { "triage": "untriaged" }
            }]
        })
    }

    fn render_interactive_v2(body: &str) -> Result<Value, mdx::Failure> {
        let source = interactive_source(body);
        let parsed = parse_artifact(&source)?;
        let input = interactive_input();
        render_verified(
            &parsed.compiled,
            HashMap::new(),
            &input,
            &json!({ "$root": { "inputs": {} } }),
        )
        .map(|(tree, _)| tree)
    }

    #[test]
    fn interactive_safe_tree_leaves_compile_and_execute_in_v2() {
        let tree = render_interactive_v2(
            r#"<><DropTarget entry="mark_triaged"><RecordCard record={props.input.records[0]} fields={["name"]} draggable={true} /></DropTarget><FacetControl entry="mark_triaged" record={props.input.records[0]} /></>"#,
        )
        .expect("interactive v2 safe tree executes");
        let authored = &tree["children"][0];
        assert_eq!(authored["type"], "Fragment");
        assert_eq!(authored["children"][0]["type"], "DropTarget");
        assert_eq!(authored["children"][0]["props"]["entry"], "mark_triaged");
        assert_eq!(
            authored["children"][0]["children"][0]["props"]["draggable"],
            true
        );
        assert_eq!(authored["children"][1]["type"], "FacetControl");
        assert_eq!(authored["children"][1]["props"]["record"]["id"], "record-1");

        // Safe-tree validation is deliberately structural. A rendered entry
        // name is inert data until the browser matches it to plan.interactions;
        // if an untrusted client invokes it anyway, the server rejects it as
        // an unknown manifest entry. The shared v1/v2 executor therefore must
        // not pretend it can cross-check the v2 manifest here.
        let inert = render_interactive_v2(r#"<DropTarget entry="not_declared" />"#)
            .expect("an undeclared entry remains inert safe-tree data");
        assert_eq!(inert["props"]["entry"], "not_declared");
    }

    #[test]
    fn placement_preview_is_a_pre_evaluated_direct_target_child() {
        let tree = render_interactive_v2(
            r#"<DropTarget entry="mark_triaged"><PlacementPreview recordId={props.input.records[0].id}><span class="dot"><Field record={props.input.records[0]} field="name" /></span></PlacementPreview></DropTarget>"#,
        )
        .expect("a direct canonical placement preview renders");
        assert_eq!(tree["type"], "DropTarget");
        let preview = &tree["children"][0];
        assert_eq!(preview["type"], "PlacementPreview");
        assert_eq!(preview["props"], json!({ "recordId": "record-1" }));
        assert_eq!(preview["children"][0]["type"], "span");
        assert_eq!(preview["children"][0]["props"]["class"], "nsa-dot");
    }

    #[test]
    fn placement_preview_remains_direct_after_helper_composition() {
        let tree = render_interactive_v2(
            r#"export const Preview = ({ record }) => <PlacementPreview recordId={record.id}><span><Field record={record} field="name" /></span></PlacementPreview>

<DropTarget entry="mark_triaged"><Preview record={props.input.records[0]} /></DropTarget>"#,
        )
        .expect("a helper-composed preview validates after authored code is fully evaluated");
        assert_eq!(tree["type"], "DropTarget");
        assert_eq!(tree["children"][0]["type"], "PlacementPreview");
        assert_eq!(tree["children"][0]["props"]["recordId"], "record-1");
    }

    #[test]
    fn placement_preview_variants_consume_the_global_output_bounds() {
        let input = interactive_input();
        let contexts = json!({});

        let mut too_many = json!({
            "type": "DropTarget", "props": { "entry": "mark_triaged" }, "children": [{
                "type": "PlacementPreview", "props": { "recordId": "record-1" },
                "children": (0..mdx::MAX_TREE_NODES).map(|_| json!({
                    "type": "span", "props": {}, "children": []
                })).collect::<Vec<_>>()
            }]
        });
        let nodes = mdx::validate_v2_tree_with_contexts(&mut too_many, &input, &contexts)
            .expect_err("preview descendants count toward the global node limit");
        assert_eq!(nodes.details["limit"], "output_nodes");

        let mut descendant = json!({ "type": "span", "props": {}, "children": [] });
        for _ in 0..mdx::MAX_TREE_DEPTH {
            descendant = json!({ "type": "div", "props": {}, "children": [descendant] });
        }
        let mut too_deep = json!({
            "type": "DropTarget", "props": { "entry": "mark_triaged" }, "children": [{
                "type": "PlacementPreview", "props": { "recordId": "record-1" },
                "children": [descendant]
            }]
        });
        let depth = mdx::validate_v2_tree_with_contexts(&mut too_deep, &input, &contexts)
            .expect_err("preview descendants count toward the global depth limit");
        assert_eq!(depth.details["limit"], "output_depth");

        let oversized = render_interactive_v2(&format!(
            "<DropTarget entry=\"mark_triaged\"><PlacementPreview recordId={{props.input.records[0].id}}><span>{{'x'.repeat({})}}</span></PlacementPreview></DropTarget>",
            mdx::MAX_OUTPUT_BYTES + 1
        ))
        .expect_err("preview descendants count toward the global serialized byte limit");
        assert_eq!(oversized.details["limit"], "output_json_bytes");
    }

    #[test]
    fn placement_preview_rejects_invalid_identity_shape_and_placement() {
        for (body, rule) in [
            (
                r#"<PlacementPreview recordId={props.input.records[0].id}><span>dot</span></PlacementPreview>"#,
                "placement_preview_direct_child",
            ),
            (
                r#"<DropTarget entry="mark_triaged"><Stack gap={1}><PlacementPreview recordId={props.input.records[0].id}><span>dot</span></PlacementPreview></Stack></DropTarget>"#,
                "placement_preview_direct_child",
            ),
            (
                r#"{(() => { const Hidden = () => <PlacementPreview recordId={props.input.records[0].id}><span>dot</span></PlacementPreview>; return <DropTarget entry="mark_triaged"><Stack gap={1}><Hidden /></Stack></DropTarget>; })()}"#,
                "placement_preview_direct_child",
            ),
            (
                r#"<DropTarget entry="mark_triaged"><PlacementPreview recordId={props.input.records[0].id} /></DropTarget>"#,
                "placement_preview_nonempty",
            ),
            (
                r#"<DropTarget entry="mark_triaged"><PlacementPreview recordId={props.input.records[0].id}><span>one</span></PlacementPreview><PlacementPreview recordId={props.input.records[0].id}><span>two</span></PlacementPreview></DropTarget>"#,
                "placement_preview_unique_record",
            ),
            (
                r#"<DropTarget entry="mark_triaged">{[props.input.records[0], props.input.records[0]].map(record => <PlacementPreview recordId={record.id}><span>dot</span></PlacementPreview>)}</DropTarget>"#,
                "placement_preview_unique_record",
            ),
        ] {
            let failure = render_interactive_v2(body).expect_err("invalid preview is refused");
            assert_eq!(failure.details["rule"], rule, "{body}");
        }

        for body in [
            r#"<DropTarget entry="mark_triaged"><PlacementPreview recordId=""><span>dot</span></PlacementPreview></DropTarget>"#,
            r#"<DropTarget entry="mark_triaged"><PlacementPreview recordId="outside"><span>dot</span></PlacementPreview></DropTarget>"#,
            r#"<DropTarget entry="mark_triaged"><PlacementPreview recordId={props.input.records[0].id} class="dot"><span>dot</span></PlacementPreview></DropTarget>"#,
        ] {
            assert!(render_interactive_v2(body).is_err(), "{body}");
        }
    }

    #[test]
    fn interactive_safe_tree_leaves_reject_bad_props_and_fabricated_records_in_v2() {
        for body in [
            r#"<FacetControl entry="mark_triaged" record={props.input.records[0]} unknown="x" />"#,
            r#"<FacetControl entry={1} record={props.input.records[0]} />"#,
            r#"<DropTarget entry={1} />"#,
            r#"<RecordCard record={props.input.records[0]} draggable="yes" />"#,
        ] {
            let failure = render_interactive_v2(body).unwrap_err();
            assert_eq!(failure.code, "mdx_output_invalid", "{body}");
        }
        let fabricated = render_interactive_v2(
            r#"<FacetControl entry="mark_triaged" record={{id:"record-1", name:"One"}} />"#,
        )
        .unwrap_err();
        assert_eq!(fabricated.code, "mdx_capability_denied");
    }

    #[test]
    fn nested_drop_targets_are_refused_and_name_the_rule() {
        // Direct child and arbitrary depth are the same rule: a drop bubbles
        // through whatever sits between the two targets, so an intervening
        // Stack does not make the second write any less real.
        for body in [
            r#"<DropTarget entry="mark_triaged"><DropTarget entry="mark_triaged" /></DropTarget>"#,
            r#"<DropTarget entry="mark_triaged"><Stack gap={2}><Stack gap={1}><DropTarget entry="mark_triaged" /></Stack></Stack></DropTarget>"#,
        ] {
            let failure = parse_artifact(&interactive_source(body))
                .expect_err("a nested DropTarget is refused at compile time");
            assert_eq!(failure.code, "mdx_policy_violation", "{body}");
            assert_eq!(failure.details["rule"], "drop_target_not_nested", "{body}");
        }
    }

    #[test]
    fn nested_drop_targets_are_refused_in_the_rendered_tree_when_composition_hides_them() {
        // The nesting here is invisible to the compile-time visitor: the inner
        // target's JSX call sits in a helper component, lexically outside the
        // outer target's subtree, and names a `Target` parameter rather than
        // `DropTarget`. Only the rendered tree shows the two nested. If this
        // ever starts failing at parse, the case has stopped testing the
        // rendered-tree half and needs re-composing.
        let body = r#"export const Nested = ({ Target }) => <Target entry="mark_triaged" />

<DropTarget entry="mark_triaged"><Nested Target={DropTarget} /></DropTarget>"#;
        parse_artifact(&interactive_source(body))
            .expect("the compile-time visitor cannot see composed nesting");
        let failure = render_interactive_v2(body)
            .expect_err("the rendered tree refuses the nesting the compiler missed");
        assert_eq!(failure.code, "mdx_policy_violation");
        assert_eq!(failure.details["rule"], "drop_target_not_nested");
    }

    #[test]
    fn one_drop_target_per_subtree_still_compiles_and_renders() {
        // The rule is about one gesture committing two writes, so it must not
        // reach past that: sibling targets each receive their own drop, and a
        // FacetControl inside a target commits on change rather than on drop,
        // which no drop gesture can also fire.
        for body in [
            r#"<DropTarget entry="mark_triaged"><RecordCard record={props.input.records[0]} fields={["name"]} draggable={true} /></DropTarget>"#,
            r#"<Stack gap={2}><DropTarget entry="mark_triaged" /><DropTarget entry="mark_triaged" /></Stack>"#,
            r#"<DropTarget entry="mark_triaged"><FacetControl entry="mark_triaged" record={props.input.records[0]} /></DropTarget>"#,
        ] {
            render_interactive_v2(body).unwrap_or_else(|failure| {
                panic!("{body} should compile and render, got {}", failure.code)
            });
        }
    }

    #[test]
    fn an_artifact_without_interactions_keeps_its_manifest_digest() {
        let source = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2", inputs: {}, module_inputs: {}, capability_requests: []
}

<Metric label="Total" value={1} />
"#;
        let parsed = parse_artifact(source).expect("interaction-free artifact compiles");
        let Manifest::Artifact(manifest) = &parsed.manifest else {
            unreachable!("artifact source yields an artifact manifest");
        };
        assert!(manifest.interactions.is_empty());
        // The empty set is skipped on the wire, so every already-attested
        // artifact keeps the manifest digest inside its compiled cache key.
        assert!(parsed.manifest.normalized().get("interactions").is_none());
    }

    #[test]
    fn invalid_interaction_entries_are_refused_and_name_the_failing_entry() {
        for (entry, expected) in [
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: {}, facet: "triage", value: { from: "literal", value: "triaged" } }"#,
                "declares no bound_input slot",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input", port: "absent" } } },
                     facet: "triage", value: { from: "literal", value: "triaged" } }"#,
                "undeclared input port 'absent'",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } } }, facet: "triage" }"#,
                "facet.set declares no value",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.unset",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "triage", value: { from: "literal", value: "triaged" } }"#,
                "facet.unset declares a value",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "triage", value: { from: "slot", slot: "choice" } }"#,
                "value names undeclared slot 'choice'",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } },
                              other: { domain: { kind: "bound_input" } } },
                     facet: "triage", value: { from: "literal", value: "triaged" } }"#,
                "declares more than one bound_input slot",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } },
                              choice: { domain: { kind: "values", values: [] } } },
                     facet: "triage", value: { from: "slot", slot: "choice" } }"#,
                "declares 0 domain members",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } },
                              spare: { domain: { kind: "values", values: ["x"] } } },
                     facet: "triage", value: { from: "literal", value: "triaged" } }"#,
                "slot 'spare' is declared but unused",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "archived", value: { from: "literal", value: "true" } }"#,
                "facet 'archived' is engine-dispatched",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "runtime", value: { from: "literal", value: "native.html.v1" } }"#,
                "facet 'runtime' is engine-dispatched",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.unset",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "blob_ref" }"#,
                "facet 'blob_ref' is engine-dispatched",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "triage", value: { from: "literal", value: true } }"#,
                "value literal is not a string, number or object",
            ),
            (
                r#"{ id: "mark_triaged", label: "A", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } },
                              choice: { domain: { kind: "values", values: ["triaged", true] } } },
                     facet: "triage", value: { from: "slot", slot: "choice" } }"#,
                "domain member that is not a string, number or object",
            ),
            (
                r#"{ id: "mark_triaged", label: "", effect: "facet.set",
                     slots: { record: { domain: { kind: "bound_input" } } },
                     facet: "triage", value: { from: "literal", value: "triaged" } }"#,
                "label is blank",
            ),
        ] {
            let failure = parse_artifact(&interaction_artifact(entry))
                .expect_err("invalid interaction entry is refused at compile");
            assert_eq!(failure.code, "interaction_entry_invalid", "{expected}");
            assert!(
                failure.message.contains(expected),
                "expected {expected:?} in {:?}",
                failure.message
            );
            assert_eq!(
                failure.details["entry_id"], "mark_triaged",
                "diagnostic must name the failing entry"
            );
        }
        let duplicate = parse_artifact(&interaction_artifact(&format!(
            "{TRIAGE_ENTRY}, {TRIAGE_ENTRY}"
        )))
        .expect_err("duplicate entry ids are refused");
        assert!(
            duplicate.message.contains("declared twice"),
            "{duplicate:?}"
        );
        let unknown_field = interaction_artifact(TRIAGE_ENTRY).replace(
            "facet: \"triage\"",
            "facet: \"triage\", scope: \"everything\"",
        );
        let scoped =
            parse_artifact(&unknown_field).expect_err("an entry cannot state its own scope");
        assert_eq!(scoped.code, "module_descriptor_invalid");
    }

    // -- board payload measurement -------------------------------------------

    /// The Backlog board's own source, as saved in the workspace it was
    /// measured against: six `DropTarget` lanes over a `triage` facet, every
    /// card declaring `fields={["kind"]}`, plus a `RecordList` for records
    /// carrying no `triage` at all.
    const BACKLOG_BOARD_SOURCE: &str = r#"export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: { board: { envelope: "native.collection-envelope.v1", required: true, expose_to_root: true } },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "board" } },
    { capability: "navigation.record.user_gesture", scope: {} }
  ],
  interactions: [
    { id: "to_untriaged", label: "Untriaged", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "untriaged" } },
    { id: "to_triaged", label: "Triaged", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "triaged" } },
    { id: "to_committed", label: "Committed", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "committed" } },
    { id: "to_shipped", label: "Shipped", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "shipped" } },
    { id: "to_merged", label: "Merged", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "merged" } },
    { id: "to_dropped", label: "Dropped", effect: "facet.set", slots: { record: { domain: { kind: "bound_input", port: "board" } } }, facet: "triage", value: { from: "literal", value: "dropped" } }
  ]
}

<div class="board">
  <div class="lane">
    <DropTarget entry="to_untriaged">
      {props.input.records.filter(r => r.facets.triage === "untriaged").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_triaged">
      {props.input.records.filter(r => r.facets.triage === "triaged").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_committed">
      {props.input.records.filter(r => r.facets.triage === "committed").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_shipped">
      {props.input.records.filter(r => r.facets.triage === "shipped").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_merged">
      {props.input.records.filter(r => r.facets.triage === "merged").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
  <div class="lane">
    <DropTarget entry="to_dropped">
      {props.input.records.filter(r => r.facets.triage === "dropped").map(r => <RecordCard record={r} fields={["kind"]} draggable={true} />)}
    </DropTarget>
  </div>
</div>

<div class="unmatched">
  <RecordList records={props.input.records.filter(r => r.facets.triage === undefined)} empty="Everything here carries a triage facet" />
</div>
"#;

    /// Synthetic records sized like the ones the board actually binds: names
    /// around 107 characters, summaries around 387, four facets. Real record
    /// text is deliberately not committed here — the field *sizes* are what
    /// the payload measurement depends on, and they are reproducible.
    fn backlog_records(count: usize) -> Value {
        let lanes = [
            ("untriaged", 128usize),
            ("triaged", 10),
            ("committed", 2),
            ("shipped", 2),
            ("merged", 1),
            ("dropped", 1),
        ];
        let mut lane_for = Vec::new();
        for (value, share) in lanes {
            for _ in 0..share {
                lane_for.push(value);
            }
        }
        let records = (0..count)
            .map(|index| {
                let triage = lane_for
                    .get(index)
                    .copied()
                    .unwrap_or("untriaged");
                json!({
                    "id": format!("{index:08x}-1111-4111-8111-111111111111"),
                    "type": "Document",
                    "kind": "note",
                    "name": format!("{index:03} {}", "observation text ".repeat(6)),
                    "summary": format!("{index:03} {}", "summary sentence about the observation ".repeat(9)),
                    "lifecycle": "open",
                    "maturity": Value::Null,
                    "persistence": "enduring",
                    "facets": {
                        "area": "artifacts",
                        "filed_by": "Claude",
                        "source": "dogfooding 2026-08-18 first-run setup",
                        "triage": triage,
                    }
                })
            })
            .collect::<Vec<_>>();
        json!({
            "version": NAMED_INPUT_ABI,
            "mode": "named",
            "inputs": {},
            "records": records
        })
    }

    /// `fields` selects what is DISPLAYED, not what is SENT.
    ///
    /// Every card on this board declares `fields={["kind"]}` and every card
    /// nevertheless carries the whole record — `name`, `summary`, the entire
    /// `facets` map, the lot. This test pins that as a fact rather than a
    /// suspicion, because it is the premise a projection change would rest on
    /// and it should fail loudly the day someone changes it.
    ///
    /// It deliberately asserts no timing. For the numbers, and for why
    /// projecting these props is not where a board's cold open goes, run
    /// `cargo run --release --features dev-tools --bin board-render-cost`:
    /// the same board through `render_artifact` takes ~31 SECONDS, ~98% of it
    /// replaying the content-event log before any of this code runs. Measured
    /// 25 Aug 2026: compile 3.6ms, execute 42.8ms, validate 0.4ms, for a
    /// 120,796-byte tree.
    #[test]
    fn a_card_ships_the_whole_record_whatever_its_fields_declare() {
        const RECORDS: usize = 144;
        let _guard = mdx::test_guard();
        let input = backlog_records(RECORDS);
        let contexts = json!({ "$root": { "inputs": {} } });

        let parsed = parse_artifact(BACKLOG_BOARD_SOURCE).expect("the board source compiles");
        let serialized = mdx::execute_v2_graph(
            &parsed.compiled,
            HashMap::new(),
            &input,
            &contexts,
            &mut mdx::ExecutionPhases::default(),
        )
        .expect("the board renders");
        let mut tree: Value = serde_json::from_str(&serialized).expect("the tree is JSON");
        mdx::validate_v2_tree(&mut tree, &input).expect("the tree validates");

        let mut cards = Vec::new();
        collect_cards(&tree, &mut cards);
        assert_eq!(cards.len(), RECORDS, "every bound record renders one card");

        let card = cards[0];
        assert_eq!(
            card["props"]["fields"],
            json!(["kind"]),
            "the board declares one displayed field"
        );
        let record = &card["props"]["record"];
        for sent in [
            "id",
            "type",
            "kind",
            "name",
            "summary",
            "lifecycle",
            "maturity",
            "persistence",
            "facets",
        ] {
            assert!(
                record.get(sent).is_some(),
                "a card declaring fields={{[\"kind\"]}} still ships '{sent}'"
            );
        }
        assert_eq!(
            record["facets"].as_object().expect("facets is a map").len(),
            4,
            "and the whole facets map with it, not just the displayed one"
        );

        // The size that follows from that, held loosely: an exact byte count
        // would be a golden nobody could update meaningfully, but the order of
        // magnitude is the finding.
        let tree_bytes = serde_json::to_string(&tree)
            .expect("the tree serializes")
            .len();
        assert!(
            tree_bytes > 100_000,
            "144 cards of whole records is a six-figure tree, got {tree_bytes}"
        );
    }

    /// Every `RecordCard` node in a safe tree, in document order.
    fn collect_cards<'tree>(node: &'tree Value, found: &mut Vec<&'tree Value>) {
        match node {
            Value::Array(values) => values.iter().for_each(|value| collect_cards(value, found)),
            Value::Object(object) => {
                if object.get("type").and_then(Value::as_str) == Some("RecordCard") {
                    found.push(node);
                }
                if let Some(children) = object.get("children") {
                    collect_cards(children, found);
                }
            }
            _ => {}
        }
    }
}
