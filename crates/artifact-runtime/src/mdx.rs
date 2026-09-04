//! `native.mdx.v1`: pinned MDX compilation, authority-free QuickJS execution,
//! and validation into the inert `native.safe-tree.v1` interchange format.
//!
//! This module intentionally has no database handle. Its temporary QuickJS
//! loader recognizes only the two compiler-owned modules and is replaced by a
//! deny-all loader before authored content runs. The only data value crossing
//! into the context is the resolved JSON input envelope; the only value crossing
//! out is JSON validated again in Rust before the workbench can see it.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use base64::Engine as _;
use markdown::mdast::Node as MdastNode;
use mdxjs::{compile, JsxRuntime, Options};
use rquickjs::loader::{Loader, Resolver};
use rquickjs::{CaughtError, Context, Ctx, Error as JsError, Function, Module, Object, Runtime};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use url::Url;

pub const RUNTIME_ID: &str = "native.mdx.v1";
pub const SAFE_TREE_VERSION: &str = "native.safe-tree.v1";
/// Prefix prepended to every author class name, in the author stylesheet and
/// in the rendered `class` prop alike.
///
/// The host's own safe-tree stylesheet names every class it owns `safe-*`
/// (plus a handful of bare utility names such as `tone-*` and `text-button`).
/// This prefix is reserved in the other direction: no host class may ever
/// begin with it. Because it is a constant and is applied to both sides of the
/// contract, an author class name can never resolve to a host class name, and
/// a host rule can never match an author-claimed class.
///
/// One condition holds this up, and it is not enforced here. Because the
/// prefix is a constant and every artifact's sheet scopes to `.safe-tree`,
/// two artifacts rendered on the same page would share both — artifact A's
/// `.nsa-card` rule would style artifact B's `.nsa-card` elements. That is
/// unreachable today: the workbench has exactly one `<SafeTree>` mount site,
/// inside the record pane's artifact surface, so one page shows one artifact.
///
/// If a second concurrent mount is ever added, this becomes a real bleed. The
/// cheap fix is a per-render scope root rather than a per-artifact class
/// prefix: the digest is already available where `css::validate` is called,
/// so the sheet can scope to `.safe-tree-<digest>` while the prefix stays
/// constant. Prefixing per artifact would instead need artifact identity
/// threaded through `validate_tree` -> `validate_value` -> `validate_props`,
/// which are shared with v1 and carry no artifact identity at all.
pub const AUTHOR_CLASS_PREFIX: &str = "nsa-";
/// Most classes one element may carry, and the longest single class name.
const MAX_AUTHOR_CLASSES: usize = 16;
const MAX_AUTHOR_CLASS_BYTES: usize = 64;
const COMPILE_PROFILE: &str = "native.mdx.compile.v1";
const COMPONENT_POLICY: &str = "native.mdx.components@1";
pub const V2_COMPONENT_POLICY_ID: &str = "native.mdx.components";
pub const V2_COMPONENT_POLICY_VERSION: u64 = 4;
pub const V2_COMPONENT_POLICY: &str = "native.mdx.components@4";
const CACHE_NAMESPACE: &str = "native.artifact-compiled-cache.v1";
const ADAPTER_REVISION: &str = "1";
const JSX_RUNTIME_MODULE: &str = "native.mdx.v1/jsx-runtime";
const PROVIDER_MODULE: &str = "native.mdx.v1/provider";
const MAX_SOURCE_BYTES: usize = 524_288;
const MAX_COMPILED_BYTES: usize = 4 * 1024 * 1024;
const MAX_INPUT_RECORDS: usize = 10_000;
const MAX_INPUT_BYTES: usize = 8_388_608;
pub(crate) const MAX_OUTPUT_BYTES: usize = 2_097_152;
pub(crate) const MAX_TREE_DEPTH: usize = 64;
pub(crate) const MAX_TREE_NODES: usize = 10_000;
const MAX_GROUPED_COUNT_BUCKETS: usize = 128;
const MAX_GROUPED_COUNT_TOTAL: u64 = 10_000;
const MAX_GROUPED_COUNT_KEY_BYTES: usize = 256;
const MAX_CHART_LABEL_BYTES: usize = 120;
const MAX_IMAGE_BYTES: usize = 262_144;
const RELATION_ENVELOPE_VERSION: &str = "native.relation-envelope.v1";
const ARTIFACT_RECORD_SCHEMA_VERSION: &str = "native.artifact-record.v1";
const MAX_JSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_INTERRUPT_TICKS: u64 = 250_000;
const MAX_CACHE_ENTRIES: usize = 64;
const MAX_CACHE_BYTES: usize = 32 * 1024 * 1024;
const MAX_BLOCKING_JOBS: usize = 4;
const MAX_TELEMETRY_EVENTS: usize = 128;

const INTRINSICS: &[&str] = &[
    "Fragment",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "p",
    "span",
    "div",
    "section",
    "article",
    "ul",
    "ol",
    "li",
    "blockquote",
    "pre",
    "code",
    "em",
    "strong",
    "del",
    "hr",
    "br",
    "table",
    "thead",
    "tbody",
    "tr",
    "th",
    "td",
    "a",
    "img",
];

const NATIVE_COMPONENTS: &[&str] = &[
    "Stack",
    "Grid",
    "Callout",
    "Badge",
    "Metric",
    "RecordList",
    "RecordTable",
    "RecordCard",
    "Field",
    "EmptyState",
];

/// Components added for writable `native.mdx.v2` safe trees. Keeping these
/// separate is the compatibility boundary: the legacy v1 runtime must keep
/// rejecting source that names them, and must keep rejecting `draggable` on
/// its otherwise-supported RecordCard.
const V2_NATIVE_COMPONENTS: &[&str] = &[
    "Stack",
    "Grid",
    "Callout",
    "Badge",
    "Metric",
    "BarChart",
    "RecordList",
    "RecordTable",
    "RecordCard",
    "FacetControl",
    "DropTarget",
    "PlacementPreview",
    "RecordCreate",
    "Field",
    "EmptyState",
];

const RECORD_FIELDS: &[&str] = &[
    "id",
    "type",
    "kind",
    "name",
    "summary",
    "lifecycle",
    "maturity",
    "persistence",
];

#[derive(Clone, Debug)]
struct CacheEntry {
    compiled: String,
    compiled_sha256: String,
    manifest_sha256: String,
    last_used: u64,
}

#[derive(Default)]
struct CompiledCache {
    entries: HashMap<String, CacheEntry>,
    bytes: usize,
    clock: u64,
}

#[derive(Clone, Debug, serde::Serialize)]
struct TelemetryEvent {
    operation: &'static str,
    artifact_id: String,
    runtime: &'static str,
    adapter_revision: u64,
    body_digest_prefix: String,
    /// Named phase durations, for a runtime whose render is not three phases.
    ///
    /// `compile`, `execute` and `validate` stay typed fields: v1 has exactly
    /// those and the aggregate counters sum them. A v2 render also replays a
    /// snapshot, resolves a module closure, reads bindings, resolves its bound
    /// inputs and assembles a plan, and none of that has a typed home. Rather
    /// than grow a field per phase and leave v1 emitting five nulls, each
    /// runtime names the phases it actually has and they land here.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    phases: BTreeMap<&'static str, u64>,
    cache_state: Option<&'static str>,
    compile_micros: Option<u64>,
    execute_micros: Option<u64>,
    validate_micros: Option<u64>,
    input_records: Option<usize>,
    input_json_bytes: Option<usize>,
    output_nodes: Option<usize>,
    output_json_bytes: Option<usize>,
    diagnostic_code: Option<String>,
    diagnostic_phase: Option<String>,
    diagnostic_limit: Option<String>,
}

impl TelemetryEvent {
    /// A `native.mdx.v1` event, identified by the digest of its source body.
    fn new(operation: &'static str, artifact_id: &str, source: &str) -> Self {
        let mut event = Self::for_runtime(operation, RUNTIME_ID, 1, artifact_id);
        event.identify(&sha256_hex(source.as_bytes()));
        event
    }

    /// An event for any runtime in this crate.
    ///
    /// `runtime` and `adapter_revision` are parameters rather than the v1
    /// constants they used to be. A v2 event that claimed `adapter_revision: 1`
    /// would be indistinguishable in the ring from a v1 one, which is the
    /// opposite of what a shared ring is for.
    fn for_runtime(
        operation: &'static str,
        runtime: &'static str,
        adapter_revision: u64,
        artifact_id: &str,
    ) -> Self {
        Self {
            operation,
            artifact_id: bounded(artifact_id, 128),
            runtime,
            adapter_revision,
            body_digest_prefix: String::new(),
            phases: BTreeMap::new(),
            cache_state: None,
            compile_micros: None,
            execute_micros: None,
            validate_micros: None,
            input_records: None,
            input_json_bytes: None,
            output_nodes: None,
            output_json_bytes: None,
            diagnostic_code: None,
            diagnostic_phase: None,
            diagnostic_limit: None,
        }
    }

    /// Name what was compiled, the way its own runtime names it.
    ///
    /// v1 digests the source body; v2 has no single body and passes its module
    /// graph cache key. Only the first 12 characters are kept, so an identity
    /// that is already a digest stays a digest, and one that is not cannot
    /// smuggle content into a snapshot that is required to be content-free.
    fn identify(&mut self, identity: &str) {
        self.body_digest_prefix = bounded(identity, 12);
    }

    fn failure(&mut self, failure: &Failure) {
        self.diagnostic_code = Some(failure.code.to_owned());
        self.diagnostic_phase = failure
            .details
            .get("phase")
            .and_then(Value::as_str)
            .map(|value| bounded(value, 32));
        self.diagnostic_limit = failure
            .details
            .get("limit")
            .and_then(Value::as_str)
            .map(|value| bounded(value, 64));
    }
}

/// The counters a single runtime contributes.
///
/// The flat `latency_micros` in the snapshot sums every runtime together. That
/// was unambiguous while only v1 emitted, and became misleading the moment v2
/// did: a board's compile and a prospective write's compile are not the same
/// question. The flat totals stay for continuity; these answer per runtime.
#[derive(Default, Clone, Debug, serde::Serialize)]
struct RuntimeTotals {
    attempts: u64,
    failures: u64,
    compile_micros: u64,
    execute_micros: u64,
    validate_micros: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    phase_micros: BTreeMap<&'static str, u64>,
}

#[derive(Default)]
struct TelemetryState {
    attempts: u64,
    failures: u64,
    cache_hits: u64,
    cache_misses: u64,
    cache_corrupt_rebuilds: u64,
    policy_denials: u64,
    limit_hits: u64,
    compile_micros: u64,
    execute_micros: u64,
    validate_micros: u64,
    runtimes: BTreeMap<&'static str, RuntimeTotals>,
    events: VecDeque<TelemetryEvent>,
}

fn telemetry() -> &'static Mutex<TelemetryState> {
    static TELEMETRY: OnceLock<Mutex<TelemetryState>> = OnceLock::new();
    TELEMETRY.get_or_init(|| Mutex::new(TelemetryState::default()))
}

fn observe(event: TelemetryEvent) {
    let mut state = telemetry().lock().expect("MDX telemetry lock poisoned");
    state.attempts = state.attempts.saturating_add(1);
    state.failures = state
        .failures
        .saturating_add(u64::from(event.diagnostic_code.is_some()));
    match event.cache_state {
        Some("hit") => state.cache_hits = state.cache_hits.saturating_add(1),
        Some("miss") => state.cache_misses = state.cache_misses.saturating_add(1),
        Some("rebuilt_corrupt") => {
            state.cache_corrupt_rebuilds = state.cache_corrupt_rebuilds.saturating_add(1)
        }
        _ => {}
    }
    if matches!(
        event.diagnostic_code.as_deref(),
        Some("mdx_policy_violation" | "mdx_capability_denied")
    ) {
        state.policy_denials = state.policy_denials.saturating_add(1);
    }
    if event.diagnostic_code.as_deref() == Some("mdx_resource_limit_exceeded") {
        state.limit_hits = state.limit_hits.saturating_add(1);
    }
    state.compile_micros = state
        .compile_micros
        .saturating_add(event.compile_micros.unwrap_or(0));
    state.execute_micros = state
        .execute_micros
        .saturating_add(event.execute_micros.unwrap_or(0));
    state.validate_micros = state
        .validate_micros
        .saturating_add(event.validate_micros.unwrap_or(0));
    let totals = state.runtimes.entry(event.runtime).or_default();
    totals.attempts = totals.attempts.saturating_add(1);
    totals.failures = totals
        .failures
        .saturating_add(u64::from(event.diagnostic_code.is_some()));
    totals.compile_micros = totals
        .compile_micros
        .saturating_add(event.compile_micros.unwrap_or(0));
    totals.execute_micros = totals
        .execute_micros
        .saturating_add(event.execute_micros.unwrap_or(0));
    totals.validate_micros = totals
        .validate_micros
        .saturating_add(event.validate_micros.unwrap_or(0));
    for (phase, micros) in &event.phases {
        let total = totals.phase_micros.entry(phase).or_default();
        *total = total.saturating_add(*micros);
    }
    if state.events.len() == MAX_TELEMETRY_EVENTS {
        state.events.pop_front();
    }
    state.events.push_back(event);
}

/// A render's phases, reported by a runtime that executes here but assembles
/// its render somewhere else.
///
/// `TelemetryEvent`, `observe` and the ring behind them are private on purpose.
/// What reaches the snapshot has to stay bounded and content-free —
/// `telemetry_is_bounded_aggregate_and_content_free` is that contract — and
/// keeping it is this module's job rather than every caller's to remember.
///
/// `native.mdx.v2` has to report anyway, because it executes here but assembles
/// its render one crate up in `src/mcp/tools/artifacts.rs`, and that is where
/// most of a board's cold open happens: replaying the snapshot, resolving the
/// module closure, resolving the bound inputs, reading each record's observed
/// facet versions. None of it is visible from inside this crate.
///
/// So this is the seam, and it is deliberately narrow. A caller can name a
/// phase and close it, and fill in the counts and the outcome an event already
/// has room for. It cannot reach the ring, the counters, or the shape of what
/// is stored.
pub struct RenderTelemetry {
    event: TelemetryEvent,
    mark: Instant,
}

impl RenderTelemetry {
    /// Open an event. The first phase starts now.
    pub fn begin(
        operation: &'static str,
        runtime: &'static str,
        adapter_revision: u64,
        artifact_id: &str,
    ) -> Self {
        Self {
            event: TelemetryEvent::for_runtime(operation, runtime, adapter_revision, artifact_id),
            mark: Instant::now(),
        }
    }

    /// Name what was compiled, once the render knows. See `identify`.
    pub fn identity(&mut self, identity: &str) {
        self.event.identify(identity);
    }

    /// Close the phase running since the last boundary, record it under `name`,
    /// and start the next one.
    ///
    /// Phases are consecutive and non-overlapping by construction, so they sum
    /// to the wall clock between `begin` and the final call. That is what makes
    /// an event answer "where did the time go" rather than "how long did these
    /// few things take", and it is why this is one moving boundary rather than
    /// a set of independent stopwatches.
    ///
    /// `compile`, `execute` and `validate` are also written to the typed fields
    /// of those names, so a v2 event answers the three questions a v1 event
    /// answers and the shared counters stay comparable. Any other name is
    /// carried in `phases` alone. A name used twice accumulates.
    pub fn phase(&mut self, name: &'static str) {
        let micros = elapsed_micros(self.mark);
        self.mark = Instant::now();
        self.record(name, micros);
    }

    /// Record `hit`, `miss` or `rebuilt_corrupt` for the runtime's own cache.
    pub fn cache_state(&mut self, state: &'static str) {
        self.event.cache_state = Some(state);
    }

    pub fn input(&mut self, records: usize, json_bytes: usize) {
        self.event.input_records = Some(records);
        self.event.input_json_bytes = Some(json_bytes);
    }

    pub fn output(&mut self, nodes: usize, json_bytes: usize) {
        self.event.output_nodes = Some(nodes);
        self.event.output_json_bytes = Some(json_bytes);
    }

    /// Record the outcome of a render that failed inside this crate.
    pub fn failed(&mut self, failure: &Failure) {
        self.event.failure(failure);
    }

    /// Record the outcome of a render that failed in the host, where the
    /// diagnostic is already JSON and nothing is `'static`.
    ///
    /// Both are bounded before they are stored. A diagnostic code is a closed
    /// vocabulary in practice, but this event is reachable from a snapshot and
    /// an unbounded string recovered from a JSON value is exactly the shape a
    /// content-free contract loses to.
    pub fn failed_with(&mut self, code: &str, phase: Option<&str>) {
        self.event.diagnostic_code = Some(bounded(code, 64));
        self.event.diagnostic_phase = phase.map(|phase| bounded(phase, 32));
    }

    /// Fold in phases measured inside a blocking worker, and close the
    /// boundary the same way `phase` would.
    ///
    /// Whatever the worker did not account for is the cost of getting onto the
    /// blocking pool and back, so it is named `blocking_dispatch` rather than
    /// dropped. Silently losing it would break the one property that makes
    /// these phases worth reading: that they sum to the render.
    pub fn absorb(&mut self, phases: ExecutionPhases) {
        let elapsed = elapsed_micros(self.mark);
        self.mark = Instant::now();
        self.record("execute", phases.execute_micros);
        self.record("output_decode", phases.decode_micros);
        self.record("validate", phases.validate_micros);
        self.record(
            "blocking_dispatch",
            elapsed.saturating_sub(
                phases
                    .execute_micros
                    .saturating_add(phases.decode_micros)
                    .saturating_add(phases.validate_micros),
            ),
        );
        self.input(phases.input_records, phases.input_json_bytes);
        self.output(phases.output_nodes, phases.output_json_bytes);
    }

    /// Accumulate, never assign — including into the three typed fields.
    ///
    /// The map has always accumulated, so assigning the typed fields would let
    /// `execute_micros` and `phases["execute"]` disagree the first time any
    /// path reported a name twice. No path does today, which is exactly why it
    /// would be found late.
    fn record(&mut self, name: &'static str, micros: u64) {
        let field = match name {
            "compile" => Some(&mut self.event.compile_micros),
            "execute" => Some(&mut self.event.execute_micros),
            "validate" => Some(&mut self.event.validate_micros),
            _ => None,
        };
        if let Some(field) = field {
            *field = Some(field.unwrap_or(0).saturating_add(micros));
        }
        let total = self.event.phases.entry(name).or_default();
        *total = total.saturating_add(micros);
    }

    /// Content-free per-render timing for an opt-in response field.
    ///
    /// Borrows only and closes no phase: the caller snapshots the phases,
    /// cache state and counts accumulated so far, then still commits the same
    /// event with `observe`. The shape mirrors what the ring receives — the
    /// same phase names and durations, plus `cache.state` — and nothing else:
    /// no artifact id, no digest, no diagnostic, no record content. Counts
    /// describe this render only.
    pub fn timing(&self) -> Value {
        json!({
            "phases": self.event.phases,
            "cache": { "state": self.event.cache_state },
            "compile_micros": self.event.compile_micros,
            "execute_micros": self.event.execute_micros,
            "validate_micros": self.event.validate_micros,
            "input_records": self.event.input_records,
            "input_json_bytes": self.event.input_json_bytes,
            "output_nodes": self.event.output_nodes,
            "output_json_bytes": self.event.output_json_bytes,
        })
    }

    /// Commit the event to the bounded ring and the counters.
    ///
    /// Takes `self`, so a render reports once and cannot report twice.
    pub fn observe(self) {
        observe(self.event);
    }
}

/// Dependency-free scrape seam for a hosting metrics/log exporter. The host may
/// poll this bounded snapshot and export its counters/events to its configured
/// backend; native-ce deliberately has no process-wide logging dependency.
pub fn telemetry_snapshot() -> Value {
    let state = telemetry().lock().expect("MDX telemetry lock poisoned");
    json!({
        "attempts": state.attempts,
        "failures": state.failures,
        "cache": {
            "hit": state.cache_hits,
            "miss": state.cache_misses,
            "rebuilt_corrupt": state.cache_corrupt_rebuilds,
        },
        "policy_denials": state.policy_denials,
        "limit_hits": state.limit_hits,
        "latency_micros": {
            "compile": state.compile_micros,
            "execute": state.execute_micros,
            "validate": state.validate_micros,
        },
        "runtimes": &state.runtimes,
        "events": state.events.iter().collect::<Vec<_>>(),
    })
}

fn cache() -> &'static Mutex<CompiledCache> {
    static CACHE: OnceLock<Mutex<CompiledCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(CompiledCache::default()))
}

fn admission() -> &'static Arc<tokio::sync::Semaphore> {
    static ADMISSION: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    ADMISSION.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(MAX_BLOCKING_JOBS)))
}

pub fn try_admit() -> Result<tokio::sync::OwnedSemaphorePermit, Failure> {
    Arc::clone(admission()).try_acquire_owned().map_err(|_| {
        Failure::new(
            "mdx_resource_limit_exceeded",
            "admission",
            "native.mdx.v1 compile/execute capacity is saturated",
        )
        .detail("limit", "blocking_pool_jobs")
        .detail("maximum", MAX_BLOCKING_JOBS as u64)
    })
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub code: &'static str,
    pub message: String,
    pub details: Value,
}

impl Failure {
    pub fn new(code: &'static str, phase: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: json!({ "phase": phase, "runtime": RUNTIME_ID, "adapter_revision": 1 }),
        }
    }

    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details
            .as_object_mut()
            .expect("failure details are an object")
            .insert(key.into(), value.into());
        self
    }
}

#[derive(Clone, Debug)]
pub struct Rendered {
    pub tree: Value,
    pub cache_state: &'static str,
    pub cache_key: String,
    pub body_sha256: String,
}

pub fn descriptor() -> Value {
    json!({
        "id": RUNTIME_ID,
        "contract_version": 1,
        "adapter_revision": 1,
        "body_media_type": "text/mdx; charset=utf-8",
        "source_encoding": "utf-8",
        "compiler": {
            "id": "mdxjs-rs",
            "crate": "mdxjs",
            "version": "1.0.4",
            "options_profile": COMPILE_PROFILE,
            "development": false,
            "jsx_runtime": "automatic",
            "jsx_import_source": RUNTIME_ID,
            "provider_import_source": PROVIDER_MODULE,
            "plugins": [],
        },
        "executor": {
            "id": "rquickjs.quickjs-ng",
            "crate": "rquickjs",
            "version": "0.11.0",
            "sys_crate": "rquickjs-sys@0.11.0",
            "profile": "native.mdx.quickjs.v1",
            "module_loader": "compiler-modules-only-before-content",
        },
        "component_policy": { "id": "native.mdx.components", "version": 1 },
        "input_envelope_version": "native.artifact-input.v1",
        "execution_profile": "sandboxed",
        "requested_capabilities": [],
        "granted_capabilities": [
            "input.read",
            "navigation.record.user_gesture",
            "navigation.external.user_gesture",
        ],
        "output_surface": "workbench.safe-tree.v1",
        "diagnostic_format": "native.artifact-diagnostic.v1",
        "limits": {
            "source_utf8_bytes": MAX_SOURCE_BYTES,
            "input_records": MAX_INPUT_RECORDS,
            "input_json_bytes": MAX_INPUT_BYTES,
            "quickjs_heap_bytes": 67_108_864,
            "quickjs_stack_bytes": 524_288,
            "execution_interrupt_ticks": MAX_INTERRUPT_TICKS,
            "output_nodes": MAX_TREE_NODES,
            "output_depth": MAX_TREE_DEPTH,
            "output_json_bytes": MAX_OUTPUT_BYTES,
            "data_image_decoded_bytes": MAX_IMAGE_BYTES,
        }
    })
}

/// Parse, apply the authored-module policy, and compile without executing.
/// Used by prospective writes as well as by cache misses on open.
pub fn validate_source(artifact_id: &str, source: &str) -> Result<(), Failure> {
    let started = Instant::now();
    let compile_started = Instant::now();
    let result = compile_source(source)
        .map(|_| ())
        .map_err(|failure| with_source_context(failure, artifact_id, source));
    let mut event = TelemetryEvent::new("validate", artifact_id, source);
    event.compile_micros = Some(elapsed_micros(compile_started));
    event.validate_micros = Some(elapsed_micros(started));
    if let Err(failure) = &result {
        event.failure(failure);
    }
    observe(event);
    result
}

#[cfg(test)]
fn render(source: &str, input: &Value) -> Result<Rendered, Failure> {
    render_partitioned("test-artifact", source, input, "test/local")
}

pub fn render_partitioned(
    artifact_id: &str,
    source: &str,
    input: &Value,
    cache_partition: &str,
) -> Result<Rendered, Failure> {
    let mut event = TelemetryEvent::new("render", artifact_id, source);
    let result = render_inner(source, input, cache_partition, &mut event)
        .map_err(|failure| with_source_context(failure, artifact_id, source));
    if let Err(failure) = &result {
        event.failure(failure);
    }
    observe(event);
    result
}

fn render_inner(
    source: &str,
    input: &Value,
    cache_partition: &str,
    event: &mut TelemetryEvent,
) -> Result<Rendered, Failure> {
    let body_sha256 = sha256_hex(source.as_bytes());
    let key = cache_key(&body_sha256);
    let storage_key = format!("{}:{key}", sha256_hex(cache_partition.as_bytes()));
    let expected_manifest = cache_manifest(&key);
    let (cached, corrupt) = cache_lookup(&storage_key, &expected_manifest);
    let (compiled, state) = match cached {
        Some(compiled) => (compiled, "hit"),
        None => {
            // Compilation is deliberately outside the global cache lock. A
            // concurrent miss may compile the same immutable source, after
            // which either equivalent value can safely win insertion.
            let compile_started = Instant::now();
            let compiled = compile_source(source);
            event.compile_micros = Some(elapsed_micros(compile_started));
            let compiled = compiled?;
            cache_insert(storage_key, cache_entry(&key, compiled.clone()));
            (compiled, if corrupt { "rebuilt_corrupt" } else { "miss" })
        }
    };
    event.cache_state = Some(state);

    let input_bytes = serde_json::to_vec(input).map_err(|_| {
        Failure::new(
            "mdx_output_invalid",
            "input",
            "artifact input is not valid JSON",
        )
    })?;
    if input_bytes.len() > MAX_INPUT_BYTES {
        return Err(Failure::new(
            "mdx_resource_limit_exceeded",
            "input",
            "resolved artifact input exceeds the runtime byte limit",
        )
        .detail("limit", "input_json_bytes")
        .detail("maximum", MAX_INPUT_BYTES as u64));
    }
    let input_records = input
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Failure::new(
                "mdx_output_invalid",
                "input",
                "artifact input records must be an array",
            )
        })?;
    event.input_records = Some(input_records.len());
    event.input_json_bytes = Some(input_bytes.len());
    if input_records.len() > MAX_INPUT_RECORDS {
        return Err(Failure::new(
            "mdx_resource_limit_exceeded",
            "input",
            "resolved artifact input exceeds the record limit",
        )
        .detail("limit", "input_records")
        .detail("maximum", MAX_INPUT_RECORDS as u64));
    }

    let execute_started = Instant::now();
    let serialized = execute(&compiled, input);
    event.execute_micros = Some(elapsed_micros(execute_started));
    let serialized = serialized.map_err(|mut failure| {
        failure = failure.detail("body_sha256", body_sha256.clone());
        failure
    })?;
    event.output_json_bytes = Some(serialized.len());
    if serialized.len() > MAX_OUTPUT_BYTES {
        return Err(Failure::new(
            "mdx_resource_limit_exceeded",
            "output",
            "safe-tree output exceeds the serialized byte limit",
        )
        .detail("limit", "output_json_bytes")
        .detail("maximum", MAX_OUTPUT_BYTES as u64));
    }
    let mut deserializer = serde_json::Deserializer::from_str(&serialized);
    deserializer.disable_recursion_limit();
    let mut tree = <Value as serde::Deserialize>::deserialize(&mut deserializer).map_err(|_| {
        Failure::new(
            "mdx_output_invalid",
            "output",
            "MDX returned a value that is not a serializable safe tree",
        )
    })?;
    deserializer.end().map_err(|_| {
        Failure::new(
            "mdx_output_invalid",
            "output",
            "MDX returned trailing data after its safe-tree value",
        )
    })?;
    event.output_nodes = Some(validate_tree(&mut tree, input)?);
    canonicalize(&mut tree);
    Ok(Rendered {
        tree,
        cache_state: state,
        cache_key: key,
        body_sha256,
    })
}

fn compile_source(source: &str) -> Result<String, Failure> {
    let body_sha256 = sha256_hex(source.as_bytes());
    compile_source_inner(source).map_err(|failure| with_body_digest(failure, &body_sha256))
}

fn compile_source_inner(source: &str) -> Result<String, Failure> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Failure::new(
            "mdx_source_too_large",
            "source",
            "MDX source exceeds 512 KiB UTF-8",
        )
        .detail("limit", "source_utf8_bytes")
        .detail("maximum", MAX_SOURCE_BYTES as u64));
    }
    if source.starts_with('\u{feff}') {
        return Err(Failure::new(
            "mdx_policy_violation",
            "source",
            "MDX source must not begin with a UTF-8 BOM",
        )
        .detail("rule", "utf8_bom"));
    }
    if source.lines().any(|line| {
        let line = line.trim_start();
        line.starts_with("import ") || line.starts_with("export ")
    }) || contains_dynamic_import(source)
    {
        return Err(Failure::new(
            "mdx_policy_violation",
            "policy",
            "authored imports and exports are forbidden by native.mdx.v1",
        )
        .detail("rule", "authored_module_syntax"));
    }

    let options = Options {
        jsx_runtime: Some(JsxRuntime::Automatic),
        jsx_import_source: Some(RUNTIME_ID.into()),
        provider_import_source: Some(PROVIDER_MODULE.into()),
        jsx: false,
        development: false,
        ..Options::default()
    };
    let compiled = compile(source, &options).map_err(|error| {
        let message = error.to_string();
        let mut failure = Failure::new(
            "mdx_compile_failed",
            "compile",
            "MDX source did not compile",
        );
        let (line, column) = parse_location(&message).unwrap_or_else(|| source_end(source));
        failure = failure.detail("line", line).detail("column", column);
        failure
    })?;

    let imports = compiled
        .lines()
        .filter_map(|line| import_specifier(line.trim()))
        .collect::<Vec<_>>();
    let expected_runtime = imports
        .iter()
        .filter(|value| **value == JSX_RUNTIME_MODULE)
        .count();
    let expected_provider = imports
        .iter()
        .filter(|value| **value == PROVIDER_MODULE)
        .count();
    if imports.len() != 2 || expected_runtime != 1 || expected_provider != 1 {
        return Err(Failure::new(
            "mdx_policy_violation",
            "inspection",
            "compiled MDX requested a module outside the binary-owned compiler modules",
        )
        .detail("rule", "compiled_module_imports"));
    }
    let export_lines = compiled
        .lines()
        .filter(|line| line.trim_start().starts_with("export "))
        .map(str::trim)
        .collect::<Vec<_>>();
    if export_lines.as_slice() != ["export default MDXContent;"]
        || contains_dynamic_import(&compiled)
    {
        return Err(Failure::new(
            "mdx_compile_failed",
            "inspection",
            "compiled MDX did not have the exact compiler-owned module shape",
        )
        .detail("rule", "compiled_module_shape"));
    }
    if compiled.len() > MAX_COMPILED_BYTES {
        return Err(Failure::new(
            "mdx_resource_limit_exceeded",
            "compile",
            "compiled MDX exceeds the adapter byte limit",
        )
        .detail("limit", "compiled_bytes")
        .detail("maximum", MAX_COMPILED_BYTES as u64));
    }
    Ok(compiled)
}

/// Compile one already-policy-validated v2 artifact/module source. The caller
/// owns exact-import and manifest validation; this seam only applies the pinned
/// compiler profile and checks that the compiler did not synthesize an ambient
/// dependency or dynamic import.
fn v2_compile_options() -> Options {
    Options {
        jsx_runtime: Some(JsxRuntime::Automatic),
        jsx_import_source: Some("native.mdx.v2".into()),
        provider_import_source: Some("native.mdx.v2/provider".into()),
        jsx: false,
        development: false,
        ..Options::default()
    }
}

#[derive(Debug)]
pub struct AuthoredEsm {
    pub source: String,
    pub start_offset: usize,
}

pub fn authored_v2_esm(source: &str) -> Result<Vec<AuthoredEsm>, Failure> {
    let tree = mdxjs::mdast_util_from_mdx(source, &v2_compile_options()).map_err(|error| {
        let message = error.to_string();
        let (line, column) = parse_location(&message).unwrap_or_else(|| source_end(source));
        Failure::new(
            "mdx_compile_failed",
            "compile",
            "MDX module source did not compile",
        )
        .detail("line", line)
        .detail("column", column)
    })?;
    let children = tree.children().ok_or_else(|| {
        Failure::new(
            "mdx_compile_failed",
            "inspection",
            "MDX source did not produce a document root",
        )
    })?;
    children
        .iter()
        .filter_map(|node| match node {
            MdastNode::MdxjsEsm(esm) => Some(esm),
            _ => None,
        })
        .map(|esm| {
            let position = esm.position.as_ref().ok_or_else(|| {
                Failure::new(
                    "mdx_compile_failed",
                    "inspection",
                    "authored ESM did not retain its source position",
                )
            })?;
            Ok(AuthoredEsm {
                source: esm.value.clone(),
                start_offset: position.start.offset,
            })
        })
        .collect()
}

pub fn compile_v2_source(source: &str) -> Result<String, Failure> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(Failure::new(
            "mdx_source_too_large",
            "source",
            "MDX module source exceeds 512 KiB UTF-8",
        )
        .detail("limit", "source_utf8_bytes")
        .detail("maximum", MAX_SOURCE_BYTES as u64));
    }
    if source.starts_with('\u{feff}') {
        return Err(Failure::new(
            "mdx_policy_violation",
            "source",
            "MDX module source must not begin with a UTF-8 BOM",
        )
        .detail("rule", "utf8_bom"));
    }
    if contains_dynamic_import(source) {
        return Err(Failure::new(
            "module_specifier_invalid",
            "policy",
            "dynamic imports are forbidden by native.mdx.v2",
        )
        .detail("rule", "dynamic_import"));
    }
    let compiled = compile(source, &v2_compile_options()).map_err(|error| {
        let message = error.to_string();
        let (line, column) = parse_location(&message).unwrap_or_else(|| source_end(source));
        Failure::new(
            "mdx_compile_failed",
            "compile",
            "MDX module source did not compile",
        )
        .detail("line", line)
        .detail("column", column)
    })?;
    if contains_dynamic_import(&compiled) {
        return Err(Failure::new(
            "module_specifier_invalid",
            "inspection",
            "compiled MDX contained a dynamic import",
        )
        .detail("rule", "dynamic_import"));
    }
    if compiled.len() > 16 * 1024 * 1024 {
        return Err(Failure::new(
            "module_closure_limit",
            "compile",
            "compiled MDX exceeds the v2 closure byte limit",
        )
        .detail("limit", "compiled_js_bytes")
        .detail("maximum", 16 * 1024 * 1024));
    }
    Ok(compiled)
}

fn with_body_digest(mut failure: Failure, body_sha256: &str) -> Failure {
    if failure.details.get("body_sha256").is_none() {
        failure = failure.detail("body_sha256", body_sha256.to_owned());
    }
    failure
}

fn with_source_context(mut failure: Failure, artifact_id: &str, source: &str) -> Failure {
    failure = with_body_digest(failure, &sha256_hex(source.as_bytes()));
    if let Some(details) = failure.details.as_object_mut() {
        details.insert("artifact_id".into(), json!(artifact_id));
        if !details.contains_key("source_range") {
            let (end_line, end_column) = source_end(source);
            let (start_line, start_column, end_line, end_column) = match (
                details.get("line").and_then(Value::as_u64),
                details.get("column").and_then(Value::as_u64),
            ) {
                (Some(line), Some(column)) => {
                    let line = line.clamp(1, end_line);
                    let line_max = source
                        .lines()
                        .nth((line - 1) as usize)
                        .map(|value| value.chars().count() as u64 + 1)
                        .unwrap_or(1);
                    let column = column.clamp(1, line_max);
                    (line, column, line, column)
                }
                _ => (1, 1, end_line, end_column),
            };
            details.insert(
                "source_range".into(),
                json!({
                    "start": { "line": start_line, "column": start_column },
                    "end": { "line": end_line, "column": end_column },
                }),
            );
        }
    }
    failure
}

fn source_end(source: &str) -> (u64, u64) {
    let mut lines = source.split('\n');
    let first = lines.next().unwrap_or_default();
    let mut line = 1u64;
    let mut column = first.chars().count() as u64 + 1;
    for value in lines {
        line += 1;
        column = value.chars().count() as u64 + 1;
    }
    (line, column)
}

fn import_specifier(line: &str) -> Option<&str> {
    if !line.starts_with("import ") {
        return None;
    }
    let (_, quoted) = line.rsplit_once(" from ")?;
    quoted
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix("\";"))
}

fn contains_dynamic_import(source: &str) -> bool {
    let bytes = source.as_bytes();
    let needle = b"import";
    let mut offset = 0;
    while let Some(index) = source[offset..].find("import") {
        let start = offset + index + needle.len();
        let rest = &bytes[start..];
        let spaces = rest
            .iter()
            .take_while(|byte| byte.is_ascii_whitespace())
            .count();
        if rest.get(spaces) == Some(&b'(') {
            return true;
        }
        offset = start;
    }
    false
}

fn execute(compiled: &str, input: &Value) -> Result<String, Failure> {
    let runtime = Runtime::new().map_err(|_| {
        Failure::new(
            "mdx_runtime_failed",
            "execute",
            "could not create QuickJS runtime",
        )
    })?;
    runtime.set_memory_limit(64 * 1024 * 1024);
    runtime.set_max_stack_size(512 * 1024);
    let ticks = Arc::new(AtomicU64::new(0));
    let tick_counter = Arc::clone(&ticks);
    // This callback runs only while QuickJS is making instruction progress. A
    // wall-clock check here would turn host scheduling pauses into user-visible
    // failures without providing a watchdog for an actually stalled callback.
    runtime.set_interrupt_handler(Some(Box::new(move || {
        tick_counter.fetch_add(1, Ordering::Relaxed) >= MAX_INTERRUPT_TICKS
    })));
    let module_gate = Arc::new(std::sync::atomic::AtomicBool::new(true));
    runtime.set_loader(
        CompilerModuleResolver {
            enabled: Arc::clone(&module_gate),
        },
        CompilerModuleLoader {
            enabled: Arc::clone(&module_gate),
        },
    );
    let context = Context::full(&runtime).map_err(|_| {
        Failure::new(
            "mdx_runtime_failed",
            "execute",
            "could not create QuickJS context",
        )
    })?;
    let input = serde_json::to_string(input).expect("artifact input JSON serialization");
    let result = context.with(|ctx| {
        let execution = (|| -> rquickjs::Result<String> {
            ctx.eval::<(), _>(runtime_prelude(&input, "{}", false))?;

            // Register and evaluate the two binary-owned compiler modules before
            // the authored module is even declared. No source-controlled module can
            // enter this registry.
            let (_, promise) =
                Module::declare(ctx.clone(), JSX_RUNTIME_MODULE, JSX_RUNTIME_SOURCE)?.eval()?;
            promise.finish::<()>()?;
            let (_, promise) =
                Module::declare(ctx.clone(), PROVIDER_MODULE, PROVIDER_SOURCE)?.eval()?;
            promise.finish::<()>()?;

            let module = Module::declare(ctx.clone(), "native.mdx.v1/root", compiled)?;
            // Resolution has completed. From this point the installed callback is
            // logically detached and rejects every request, including import().
            module_gate.store(false, Ordering::Release);
            let (module, promise) = module.eval()?;
            promise.finish::<()>()?;
            let content: Function<'_> = module.get("default")?;
            let bridge: Object<'_> = ctx.globals().get("__nativeBridge")?;
            let invoke: Function<'_> = bridge.get("invoke")?;
            invoke.call((content,))
        })();
        execution.map_err(|error| match CaughtError::from_error(&ctx, error) {
            CaughtError::Exception(exception) => exception
                .message()
                .unwrap_or_else(|| "QuickJS exception without a message".into()),
            CaughtError::Value(_) => "QuickJS non-Error exception".into(),
            CaughtError::Error(error) => error.to_string(),
        })
    });
    match result {
        Ok(value) => {
            let envelope: Value = serde_json::from_str(&value).map_err(|_| {
                Failure::new(
                    "mdx_output_invalid",
                    "execute",
                    "QuickJS returned an invalid bridge envelope",
                )
            })?;
            if envelope.get("ok").and_then(Value::as_bool) == Some(true) {
                return envelope
                    .get("encoded")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        Failure::new(
                            "mdx_output_invalid",
                            "execute",
                            "QuickJS omitted the safe-tree payload",
                        )
                    });
            }
            let message = envelope
                .get("message")
                .and_then(Value::as_str)
                .map(|value| bounded(value, 300))
                .unwrap_or_else(|| "unknown JavaScript failure".into());
            Err(classify_runtime_failure(&message))
        }
        Err(error) => {
            let resource = ticks.load(Ordering::Relaxed) >= MAX_INTERRUPT_TICKS;
            if resource {
                Err(Failure::new(
                    "mdx_resource_limit_exceeded",
                    "execute",
                    "MDX execution exceeded its deterministic instruction budget",
                )
                .detail("limit", "interrupt_ticks")
                .detail("maximum", MAX_INTERRUPT_TICKS))
            } else {
                let message = bounded(&error.to_string(), 300);
                Err(classify_runtime_failure(&message))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct RuntimeOriginFrame {
    origin_key: String,
    export: String,
    edge_key: Option<String>,
}

#[derive(Debug, Default)]
struct RuntimeOriginChannel {
    active: Vec<RuntimeOriginFrame>,
    captured: HashMap<u64, Vec<RuntimeOriginFrame>>,
    selected: Option<u64>,
    next_capture: u64,
}

impl RuntimeOriginChannel {
    fn enter(&mut self, origin_key: String, export: String, edge_key: Option<String>) {
        self.active.push(RuntimeOriginFrame {
            origin_key,
            export,
            edge_key,
        });
    }

    fn capture(&mut self) -> u64 {
        self.next_capture = self.next_capture.saturating_add(1);
        let capture = self.next_capture;
        self.captured.insert(capture, self.active.clone());
        capture
    }

    fn select(&mut self, capture: u64) {
        if self.captured.contains_key(&capture) {
            self.selected = Some(capture);
        }
    }

    fn clear_selection(&mut self) {
        self.selected = None;
    }

    fn exit(&mut self) {
        self.active.pop();
    }

    fn reset_after_module_evaluation(&mut self) {
        self.active.clear();
        self.captured.clear();
        self.selected = None;
    }

    fn failure_frames(&self) -> Option<&[RuntimeOriginFrame]> {
        if self.active.is_empty() {
            self.selected
                .and_then(|capture| self.captured.get(&capture))
                .map(Vec::as_slice)
        } else {
            Some(&self.active)
        }
    }
}

fn attribute_engine_owned_origin(
    mut failure: Failure,
    channel: &Arc<Mutex<RuntimeOriginChannel>>,
) -> Failure {
    let channel = channel
        .lock()
        .expect("v2 runtime origin channel lock poisoned");
    let Some(frames) = channel.failure_frames() else {
        return failure;
    };
    let Some(origin) = frames.last() else {
        return failure;
    };
    failure = failure
        .detail("runtime_origin_key", bounded(&origin.origin_key, 128))
        .detail("export", bounded(&origin.export, 128));
    let chain = frames
        .iter()
        .filter_map(|frame| frame.edge_key.as_deref())
        .take(64)
        .map(|key| bounded(key, 128))
        .collect::<Vec<_>>();
    if !chain.is_empty() {
        failure = failure.detail("runtime_import_chain_keys", chain);
    }
    failure
}

/// Execute a fully verified, in-memory v2 module graph. `modules` contains only
/// compiler-owned modules, immutable release modules, and host-generated edge
/// wrappers. The resolver never consults disk, packages, names, or the network,
/// and is detached immediately after the root graph resolves.
/// What a v2 render measured inside the blocking worker that ran it.
///
/// A `RenderTelemetry` cannot cross `spawn_blocking` by reference and the
/// render needs it either side of the call, so the worker measures into this
/// plain value instead and the caller folds it back in with
/// `RenderTelemetry::absorb`.
#[derive(Default, Clone, Copy, Debug)]
pub struct ExecutionPhases {
    pub execute_micros: u64,
    pub decode_micros: u64,
    pub validate_micros: u64,
    pub input_records: usize,
    pub input_json_bytes: usize,
    pub output_nodes: usize,
    pub output_json_bytes: usize,
}

pub fn execute_v2_graph(
    root_compiled: &str,
    modules: HashMap<String, String>,
    input: &Value,
    contexts: &Value,
    phases: &mut ExecutionPhases,
) -> Result<String, Failure> {
    #[derive(Debug)]
    struct RuntimeErrorInfo {
        message: String,
    }

    validate_relation_inputs(contexts)?;
    let input_bytes = serde_json::to_vec(input).map_err(|_| {
        Failure::new(
            "mdx_output_invalid",
            "input",
            "v2 artifact input is not valid JSON",
        )
    })?;
    if input_bytes.len() > MAX_INPUT_BYTES {
        return Err(Failure::new(
            "mdx_resource_limit_exceeded",
            "input",
            "resolved v2 artifact input exceeds the runtime byte limit",
        )
        .detail("limit", "input_json_bytes")
        .detail("maximum", MAX_INPUT_BYTES as u64));
    }
    let input_records = input
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            Failure::new(
                "mdx_output_invalid",
                "input",
                "v2 artifact input records must be an array",
            )
        })?;
    // Recorded here rather than recomputed by the caller: both numbers are
    // already paid for above, and re-serializing a 144-record input purely to
    // measure it would make the measurement part of what it measures.
    phases.input_json_bytes = input_bytes.len();
    phases.input_records = input_records.len();
    if input_records.len() > MAX_INPUT_RECORDS {
        return Err(Failure::new(
            "mdx_resource_limit_exceeded",
            "input",
            "resolved v2 artifact input exceeds the record limit",
        )
        .detail("limit", "input_records")
        .detail("maximum", MAX_INPUT_RECORDS as u64));
    }
    let runtime = Runtime::new().map_err(|_| {
        Failure::new(
            "mdx_runtime_failed",
            "execute",
            "could not create QuickJS runtime",
        )
    })?;
    runtime.set_memory_limit(64 * 1024 * 1024);
    runtime.set_max_stack_size(512 * 1024);
    let ticks = Arc::new(AtomicU64::new(0));
    let tick_counter = Arc::clone(&ticks);
    // Keep this budget instruction-based for the same reason as the v1 path:
    // elapsed wall time at an interrupt callback includes host scheduling time.
    runtime.set_interrupt_handler(Some(Box::new(move || {
        tick_counter.fetch_add(1, Ordering::Relaxed) >= MAX_INTERRUPT_TICKS
    })));
    let gate = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let mut sources = modules;
    sources.insert(
        "native.mdx.v2/jsx-runtime".into(),
        JSX_RUNTIME_SOURCE.into(),
    );
    sources.insert("native.mdx.v2/provider".into(), PROVIDER_SOURCE.into());
    let sources = Arc::new(sources);
    runtime.set_loader(
        VerifiedModuleResolver {
            enabled: Arc::clone(&gate),
            sources: Arc::clone(&sources),
        },
        VerifiedModuleLoader {
            enabled: Arc::clone(&gate),
            sources,
        },
    );
    let context = Context::full(&runtime).map_err(|_| {
        Failure::new(
            "mdx_runtime_failed",
            "execute",
            "could not create QuickJS context",
        )
    })?;
    let input = serde_json::to_string(input).expect("v2 input JSON serialization");
    let contexts = serde_json::to_string(contexts).expect("v2 contexts JSON serialization");
    let origin_channel = Arc::new(Mutex::new(RuntimeOriginChannel::default()));
    let execution_origins = Arc::clone(&origin_channel);
    let result = context.with(|ctx| {
        let execution = (|| -> rquickjs::Result<String> {
            let enter_origins = Arc::clone(&execution_origins);
            ctx.globals().set(
                "__nativeOriginEnter",
                Function::new(
                    ctx.clone(),
                    move |origin_key: String, export: String, edge_key: Option<String>| {
                        enter_origins
                            .lock()
                            .expect("v2 runtime origin channel lock poisoned")
                            .enter(origin_key, export, edge_key);
                    },
                )?,
            )?;
            let capture_origins = Arc::clone(&execution_origins);
            ctx.globals().set(
                "__nativeOriginCapture",
                Function::new(ctx.clone(), move || -> u64 {
                    capture_origins
                        .lock()
                        .expect("v2 runtime origin channel lock poisoned")
                        .capture()
                })?,
            )?;
            let select_origins = Arc::clone(&execution_origins);
            ctx.globals().set(
                "__nativeOriginSelect",
                Function::new(ctx.clone(), move |capture: u64| {
                    select_origins
                        .lock()
                        .expect("v2 runtime origin channel lock poisoned")
                        .select(capture);
                })?,
            )?;
            let clear_origins = Arc::clone(&execution_origins);
            ctx.globals().set(
                "__nativeOriginClear",
                Function::new(ctx.clone(), move || {
                    clear_origins
                        .lock()
                        .expect("v2 runtime origin channel lock poisoned")
                        .clear_selection();
                })?,
            )?;
            let exit_origins = Arc::clone(&execution_origins);
            ctx.globals().set(
                "__nativeOriginExit",
                Function::new(ctx.clone(), move || {
                    exit_origins
                        .lock()
                        .expect("v2 runtime origin channel lock poisoned")
                        .exit();
                })?,
            )?;
            ctx.eval::<(), _>(runtime_prelude(&input, &contexts, true))?;
            let root = Module::declare(ctx.clone(), "native.mdx.v2/root", root_compiled)?;
            gate.store(false, Ordering::Release);
            let (root, promise) = root.eval()?;
            promise.finish::<()>()?;
            execution_origins
                .lock()
                .expect("v2 runtime origin channel lock poisoned")
                .reset_after_module_evaluation();
            let content: Function<'_> = root.get("default")?;
            let bridge: Object<'_> = ctx.globals().get("__nativeBridge")?;
            let invoke: Function<'_> = bridge.get("invoke")?;
            invoke.call((content,))
        })();
        execution.map_err(|error| match CaughtError::from_error(&ctx, error) {
            CaughtError::Exception(exception) => RuntimeErrorInfo {
                message: exception
                    .message()
                    .unwrap_or_else(|| "QuickJS exception without a message".into()),
            },
            CaughtError::Value(_) => RuntimeErrorInfo {
                message: "QuickJS non-Error exception".into(),
            },
            CaughtError::Error(error) => RuntimeErrorInfo {
                message: error.to_string(),
            },
        })
    });
    match result {
        Ok(value) => {
            let envelope: Value = serde_json::from_str(&value).map_err(|_| {
                Failure::new(
                    "mdx_output_invalid",
                    "execute",
                    "QuickJS returned an invalid bridge envelope",
                )
            })?;
            if envelope.get("ok").and_then(Value::as_bool) == Some(true) {
                return envelope
                    .get("encoded")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        Failure::new(
                            "mdx_output_invalid",
                            "execute",
                            "QuickJS omitted the safe-tree payload",
                        )
                    });
            }
            let message = envelope
                .get("message")
                .and_then(Value::as_str)
                .map(|value| bounded(value, 300))
                .unwrap_or_else(|| "unknown JavaScript failure".into());
            Err(attribute_engine_owned_origin(
                classify_runtime_failure(&message),
                &origin_channel,
            ))
        }
        Err(error) => {
            if ticks.load(Ordering::Relaxed) >= MAX_INTERRUPT_TICKS {
                Err(attribute_engine_owned_origin(
                    Failure::new(
                        "mdx_resource_limit_exceeded",
                        "execute",
                        "MDX execution exceeded its deterministic instruction budget",
                    )
                    .detail("limit", "interrupt_ticks")
                    .detail("maximum", MAX_INTERRUPT_TICKS),
                    &origin_channel,
                ))
            } else {
                Err(attribute_engine_owned_origin(
                    classify_runtime_failure(&bounded(&error.message, 300)),
                    &origin_channel,
                ))
            }
        }
    }
}

fn input_failure(message: impl Into<String>) -> Failure {
    Failure::new("mdx_output_invalid", "input", message)
}

fn input_limit_failure(limit: &'static str, maximum: usize) -> Failure {
    Failure::new(
        "mdx_resource_limit_exceeded",
        "input",
        format!("MDX input exceeded {limit}"),
    )
    .detail("limit", limit)
    .detail("maximum", maximum as u64)
}

fn exact_input_object<'a>(
    value: &'a Value,
    keys: &[&str],
    subject: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| input_failure(format!("{subject} must be an object")))?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(input_failure(format!(
            "{subject} must contain exactly its declared fields"
        )));
    }
    Ok(object)
}

fn validate_relation_inputs(contexts: &Value) -> Result<(), Failure> {
    let contexts = contexts
        .as_object()
        .ok_or_else(|| input_failure("v2 artifact contexts must be an object"))?;
    for context in contexts.values() {
        let Some(inputs) = context.get("inputs").and_then(Value::as_object) else {
            continue;
        };
        for envelope in inputs.values().filter(|envelope| {
            envelope.get("version").and_then(Value::as_str) == Some(RELATION_ENVELOPE_VERSION)
                || envelope.get("relation").is_some()
        }) {
            validate_relation_envelope(envelope)?;
        }
    }
    Ok(())
}

fn validate_relation_envelope(envelope: &Value) -> Result<(), Failure> {
    let envelope = exact_input_object(
        envelope,
        &["version", "source", "relation"],
        "relation envelope",
    )?;
    if envelope.get("version").and_then(Value::as_str) != Some(RELATION_ENVELOPE_VERSION) {
        return Err(input_failure("relation envelope version is unsupported"));
    }
    let source_value = envelope.get("source").expect("closed envelope key");
    let source_fields = if source_value.get("execution_receipt").is_some() {
        &[
            "kind",
            "id",
            "collection_kind",
            "binding_revision",
            "content_revision",
            "execution_receipt",
        ][..]
    } else {
        &[
            "kind",
            "id",
            "collection_kind",
            "binding_revision",
            "content_revision",
        ][..]
    };
    let source = exact_input_object(source_value, source_fields, "relation source")?;
    if source.get("kind").and_then(Value::as_str) != Some("collection")
        || ["id", "collection_kind"].into_iter().any(|field| {
            source
                .get(field)
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
        })
    {
        return Err(input_failure("relation source identity is invalid"));
    }
    let binding = exact_input_object(
        source
            .get("binding_revision")
            .expect("closed relation source key"),
        &["kind", "value"],
        "relation binding revision",
    )?;
    if binding.get("kind").and_then(Value::as_str) != Some("binding_event_seq")
        || binding
            .get("value")
            .and_then(Value::as_u64)
            .is_none_or(|value| value > MAX_JSON_SAFE_INTEGER)
    {
        return Err(input_failure("relation binding revision is invalid"));
    }
    let revision_value = source
        .get("content_revision")
        .expect("closed relation source key");
    let opaque_revision =
        revision_value.get("kind").and_then(Value::as_str) == Some("opaque_snapshot");
    match revision_value.get("kind").and_then(Value::as_str) {
        Some("content_event_seq") => {
            let revision = exact_input_object(
                revision_value,
                &["kind", "id", "value"],
                "relation content revision",
            )?;
            if revision
                .get("id")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
                || revision
                    .get("value")
                    .and_then(Value::as_u64)
                    .is_none_or(|value| value > MAX_JSON_SAFE_INTEGER)
            {
                return Err(input_failure("relation content revision is invalid"));
            }
        }
        Some("opaque_snapshot") => {
            let revision = exact_input_object(
                revision_value,
                &["kind", "token"],
                "relation content revision",
            )?;
            if revision
                .get("token")
                .and_then(Value::as_str)
                .is_none_or(|token| {
                    !token.starts_with("native.snapshot.v1.")
                        || token.len() != "native.snapshot.v1.".len() + 64
                        || token["native.snapshot.v1.".len()..]
                            .bytes()
                            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
                })
            {
                return Err(input_failure("relation opaque snapshot token is invalid"));
            }
        }
        _ => return Err(input_failure("relation content revision is invalid")),
    }
    let relation_value = envelope.get("relation").expect("closed envelope key");
    match relation_value.get("grain").and_then(Value::as_str) {
        Some("record") if !opaque_revision && source.get("execution_receipt").is_none() => {
            validate_record_relation(relation_value)
        }
        Some("governed_sql") if opaque_revision => {
            validate_governed_sql_relation(relation_value)?;
            validate_governed_sql_execution_receipt(
                source
                    .get("execution_receipt")
                    .ok_or_else(|| input_failure("governed SQL execution receipt is missing"))?,
                relation_value,
            )
        }
        Some("record" | "governed_sql") => Err(input_failure(
            "relation grain and content revision kind are inconsistent",
        )),
        _ => Err(input_failure("relation grain is unsupported")),
    }
}

fn validate_governed_sql_execution_receipt(
    receipt: &Value,
    relation: &Value,
) -> Result<(), Failure> {
    let receipt = exact_input_object(
        receipt,
        &[
            "version",
            "observed_at",
            "row_count",
            "truncated",
            "completeness",
            "replayable",
            "observation_window_hours",
            "catalog_revision",
            "relations",
            "degraded_sources",
        ],
        "governed SQL execution receipt",
    )?;
    let observation_window_is_valid = match receipt.get("observation_window_hours") {
        Some(Value::Null) => true,
        Some(value) => value
            .as_u64()
            .is_some_and(|value| value <= MAX_JSON_SAFE_INTEGER),
        None => false,
    };
    if receipt.get("version").and_then(Value::as_str) != Some("native.governed-sql-port-receipt.v1")
        || receipt
            .get("observed_at")
            .and_then(Value::as_str)
            .is_none_or(|value| chrono::DateTime::parse_from_rfc3339(value).is_err())
        || receipt
            .get("row_count")
            .and_then(Value::as_u64)
            .is_none_or(|value| value > MAX_JSON_SAFE_INTEGER)
        || receipt.get("truncated").and_then(Value::as_bool).is_none()
        || receipt.get("replayable").and_then(Value::as_bool).is_none()
        || receipt
            .get("catalog_revision")
            .and_then(Value::as_u64)
            .is_none_or(|value| value == 0 || value > MAX_JSON_SAFE_INTEGER)
        || !observation_window_is_valid
    {
        return Err(input_failure(
            "governed SQL execution receipt scalar metadata is invalid",
        ));
    }
    let completeness = receipt.get("completeness").and_then(Value::as_str);
    if !matches!(completeness, Some("complete" | "truncated" | "best_effort")) {
        return Err(input_failure(
            "governed SQL execution receipt completeness is invalid",
        ));
    }
    let relations = receipt
        .get("relations")
        .and_then(Value::as_array)
        .filter(|relations| !relations.is_empty())
        .ok_or_else(|| input_failure("governed SQL execution receipt relations are invalid"))?;
    let mut names = BTreeSet::new();
    for relation in relations {
        let relation = exact_input_object(
            relation,
            &["name", "identity", "semantic_version"],
            "governed SQL execution receipt relation",
        )?;
        let name = relation
            .get("name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| input_failure("governed SQL execution receipt relation is invalid"))?;
        if !names.insert(name)
            || relation
                .get("identity")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            || relation
                .get("semantic_version")
                .and_then(Value::as_u64)
                .is_none_or(|value| value == 0 || value > MAX_JSON_SAFE_INTEGER)
        {
            return Err(input_failure(
                "governed SQL execution receipt relation is invalid",
            ));
        }
    }
    let degraded = receipt
        .get("degraded_sources")
        .and_then(Value::as_array)
        .ok_or_else(|| input_failure("governed SQL degraded sources are invalid"))?;
    let mut sources = BTreeSet::new();
    if degraded.iter().any(|source| {
        source
            .as_str()
            .filter(|value| !value.is_empty() && value.len() <= 128)
            .is_none_or(|value| !sources.insert(value))
    }) {
        return Err(input_failure("governed SQL degraded sources are invalid"));
    }
    let extent = relation
        .get("extent")
        .and_then(Value::as_object)
        .expect("validated governed SQL relation extent");
    if receipt.get("row_count") != extent.get("returned")
        || receipt.get("truncated") != extent.get("truncated")
        || receipt.get("completeness") != extent.get("source_completeness")
    {
        return Err(input_failure(
            "governed SQL execution receipt conflicts with relation extent",
        ));
    }
    Ok(())
}

fn bounded_relation_rows<'a>(
    relation: &'a Map<String, Value>,
    label: &str,
) -> Result<&'a Vec<Value>, Failure> {
    let rows = relation
        .get("rows")
        .and_then(Value::as_array)
        .ok_or_else(|| input_failure(format!("{label} rows must be an array")))?;
    if rows.len() > MAX_INPUT_RECORDS {
        return Err(input_limit_failure("input_records", MAX_INPUT_RECORDS));
    }
    let mut canonical_rows = Value::Array(rows.clone());
    canonicalize(&mut canonical_rows);
    let row_bytes = serde_json::to_vec(&canonical_rows)
        .map_err(|_| input_failure(format!("{label} rows are not valid JSON")))?;
    if row_bytes.len() > MAX_INPUT_BYTES {
        return Err(input_limit_failure("input_json_bytes", MAX_INPUT_BYTES));
    }
    let digest = relation.get("rows_sha256").and_then(Value::as_str);
    if digest != Some(sha256_hex(&row_bytes).as_str()) {
        return Err(input_failure(format!("{label} digest is invalid")));
    }
    Ok(rows)
}

fn validate_record_relation(relation: &Value) -> Result<(), Failure> {
    let relation = exact_input_object(
        relation,
        &[
            "grain",
            "key",
            "row_schema",
            "extent",
            "rows",
            "rows_sha256",
        ],
        "record relation",
    )?;
    if relation.get("key") != Some(&json!(["id"]))
        || relation.get("row_schema").and_then(Value::as_str)
            != Some(ARTIFACT_RECORD_SCHEMA_VERSION)
    {
        return Err(input_failure("record relation shape is unsupported"));
    }
    let rows = bounded_relation_rows(relation, "record relation")?;
    let count = rows.len() as u64;
    let extent = exact_input_object(
        relation.get("extent").expect("closed relation key"),
        &["complete", "returned", "total"],
        "record relation extent",
    )?;
    if extent.get("complete").and_then(Value::as_bool) != Some(true)
        || extent.get("returned").and_then(Value::as_u64) != Some(count)
        || extent.get("total").and_then(Value::as_u64) != Some(count)
    {
        return Err(input_failure("record relation extent is inconsistent"));
    }
    let mut ids = BTreeSet::new();
    for row in rows {
        let row = exact_input_object(
            row,
            &[
                "id",
                "type",
                "kind",
                "name",
                "summary",
                "lifecycle_interpretation",
                "maturity",
                "persistence",
                "facets",
            ],
            "artifact record row",
        )?;
        let id = row
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| input_failure("artifact record row id is invalid"))?;
        if !ids.insert(id) {
            return Err(input_failure("record relation keys must be unique"));
        }
        if row.get("type").and_then(Value::as_str).is_none()
            || row.get("name").and_then(Value::as_str).is_none()
            || !matches!(row.get("kind"), Some(Value::String(_) | Value::Null))
            || !matches!(row.get("summary"), Some(Value::String(_) | Value::Null))
            || !matches!(row.get("maturity"), Some(Value::String(_) | Value::Null))
            || !matches!(row.get("persistence"), Some(Value::String(_) | Value::Null))
            || !matches!(row.get("lifecycle_interpretation"), Some(Value::Object(_)))
            || !matches!(row.get("facets"), Some(Value::Object(_)))
        {
            return Err(input_failure("artifact record row shape is invalid"));
        }
    }
    Ok(())
}

fn validate_governed_sql_relation(relation: &Value) -> Result<(), Failure> {
    let relation = exact_input_object(
        relation,
        &[
            "grain",
            "key",
            "columns",
            "schema_sha256",
            "extent",
            "rows",
            "rows_sha256",
        ],
        "governed SQL relation",
    )?;
    let columns = relation
        .get("columns")
        .and_then(Value::as_array)
        .filter(|columns| !columns.is_empty())
        .ok_or_else(|| input_failure("governed SQL columns must be a non-empty array"))?;
    let schema_digest = relation.get("schema_sha256").and_then(Value::as_str);
    let mut canonical_columns = Value::Array(columns.clone());
    canonicalize(&mut canonical_columns);
    let expected_schema = sha256_hex(
        &serde_json::to_vec(&canonical_columns)
            .map_err(|_| input_failure("governed SQL columns are not valid JSON"))?,
    );
    if schema_digest != Some(expected_schema.as_str()) {
        return Err(input_failure("governed SQL schema digest is invalid"));
    }
    let mut declared = BTreeMap::<&str, (&str, bool)>::new();
    for column in columns {
        let column =
            exact_input_object(column, &["name", "type", "nullable"], "governed SQL column")?;
        let name = column
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| input_failure("governed SQL column name is invalid"))?;
        let kind = column
            .get("type")
            .and_then(Value::as_str)
            .filter(|kind| {
                matches!(
                    *kind,
                    "identifier"
                        | "boolean"
                        | "integer"
                        | "real"
                        | "text"
                        | "bytes"
                        | "json"
                        | "timestamp"
                )
            })
            .ok_or_else(|| input_failure("governed SQL column type is invalid"))?;
        let nullable = column
            .get("nullable")
            .and_then(Value::as_bool)
            .ok_or_else(|| input_failure("governed SQL column nullability is invalid"))?;
        if declared.insert(name, (kind, nullable)).is_some() {
            return Err(input_failure("governed SQL column names must be unique"));
        }
    }
    let key = relation
        .get("key")
        .and_then(Value::as_array)
        .filter(|key| key.len() == 1)
        .ok_or_else(|| input_failure("governed SQL relation requires one stable key"))?;
    let key = key[0]
        .as_str()
        .ok_or_else(|| input_failure("governed SQL relation key is invalid"))?;
    if declared.get(key) != Some(&("identifier", false)) {
        return Err(input_failure(
            "governed SQL relation key must be a non-null identifier",
        ));
    }
    let rows = bounded_relation_rows(relation, "governed SQL relation")?;
    let mut identities = BTreeSet::new();
    for row in rows {
        let row = row
            .as_object()
            .ok_or_else(|| input_failure("governed SQL row must be an object"))?;
        if row.len() != declared.len() || declared.keys().any(|name| !row.contains_key(*name)) {
            return Err(input_failure(
                "governed SQL row does not match its declared columns",
            ));
        }
        for (name, (kind, nullable)) in &declared {
            let value = &row[*name];
            if value.is_null() {
                if !nullable {
                    return Err(input_failure("governed SQL non-null column is null"));
                }
                continue;
            }
            let valid = match *kind {
                "identifier" | "text" => value.is_string(),
                "bytes" => value.as_str().is_some_and(|value| {
                    use base64::Engine as _;
                    base64::engine::general_purpose::STANDARD
                        .decode(value)
                        .is_ok()
                }),
                "json" => value
                    .as_str()
                    .is_some_and(|value| serde_json::from_str::<Value>(value).is_ok()),
                "timestamp" => value
                    .as_str()
                    .is_some_and(|value| chrono::DateTime::parse_from_rfc3339(value).is_ok()),
                "boolean" => value.is_boolean() || matches!(value.as_i64(), Some(0 | 1)),
                "integer" => value.as_i64().is_some(),
                "real" => value.is_number(),
                _ => false,
            };
            if !valid {
                return Err(input_failure("governed SQL row value has the wrong type"));
            }
        }
        let identity = row
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| input_failure("governed SQL row key is invalid"))?;
        if !identities.insert(identity) {
            return Err(input_failure("governed SQL relation keys must be unique"));
        }
    }
    let count = rows.len() as u64;
    let extent = exact_input_object(
        relation.get("extent").expect("closed relation key"),
        &[
            "complete",
            "returned",
            "total",
            "truncated",
            "source_completeness",
        ],
        "governed SQL relation extent",
    )?;
    let truncated = extent.get("truncated").and_then(Value::as_bool);
    let completeness = extent.get("source_completeness").and_then(Value::as_str);
    let invalid_tuple = !matches!(
        (truncated, completeness),
        (Some(false), Some("complete" | "best_effort"))
            | (Some(true), Some("truncated" | "best_effort"))
    );
    if invalid_tuple
        || extent.get("returned").and_then(Value::as_u64) != Some(count)
        || match truncated {
            Some(true) => {
                extent.get("complete").and_then(Value::as_bool) != Some(false)
                    || !extent.get("total").is_some_and(Value::is_null)
            }
            Some(false) => {
                extent.get("complete").and_then(Value::as_bool) != Some(true)
                    || extent.get("total").and_then(Value::as_u64) != Some(count)
            }
            None => true,
        }
    {
        return Err(input_failure(
            "governed SQL relation extent is inconsistent",
        ));
    }
    Ok(())
}

const JSX_RUNTIME_SOURCE: &str = r#"
const bridge = globalThis.__nativeBridge;
export const Fragment = bridge.Fragment;
export const jsx = bridge.jsx;
export const jsxs = bridge.jsxs;
"#;

const PROVIDER_SOURCE: &str = r#"
const components = globalThis.__nativeBridge.components;
export function useMDXComponents() { return components; }
"#;

struct CompilerModuleResolver {
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

impl Resolver for CompilerModuleResolver {
    fn resolve<'js>(
        &mut self,
        _ctx: &Ctx<'js>,
        base: &str,
        name: &str,
    ) -> rquickjs::Result<String> {
        if self.enabled.load(Ordering::Acquire)
            && matches!(name, JSX_RUNTIME_MODULE | PROVIDER_MODULE)
        {
            Ok(name.into())
        } else {
            Err(JsError::new_resolving_message(
                base,
                name,
                "native.mdx.v1 module loading is detached",
            ))
        }
    }
}

struct CompilerModuleLoader {
    enabled: Arc<std::sync::atomic::AtomicBool>,
}

struct VerifiedModuleResolver {
    enabled: Arc<std::sync::atomic::AtomicBool>,
    sources: Arc<HashMap<String, String>>,
}

impl Resolver for VerifiedModuleResolver {
    fn resolve<'js>(
        &mut self,
        _ctx: &Ctx<'js>,
        base: &str,
        name: &str,
    ) -> rquickjs::Result<String> {
        if self.enabled.load(Ordering::Acquire) && self.sources.contains_key(name) {
            Ok(name.into())
        } else {
            Err(JsError::new_resolving_message(
                base,
                name,
                "native.mdx.v2 verified module loading is detached",
            ))
        }
    }
}

struct VerifiedModuleLoader {
    enabled: Arc<std::sync::atomic::AtomicBool>,
    sources: Arc<HashMap<String, String>>,
}

impl Loader for VerifiedModuleLoader {
    fn load<'js>(&mut self, ctx: &Ctx<'js>, name: &str) -> rquickjs::Result<Module<'js>> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(JsError::new_loading_message(
                name,
                "native.mdx.v2 verified module loading is detached",
            ));
        }
        let source = self.sources.get(name).ok_or_else(|| {
            JsError::new_loading_message(name, "module is outside the verified closure")
        })?;
        Module::declare(ctx.clone(), name, source.as_str())
    }
}

impl Loader for CompilerModuleLoader {
    fn load<'js>(&mut self, ctx: &Ctx<'js>, name: &str) -> rquickjs::Result<Module<'js>> {
        if !self.enabled.load(Ordering::Acquire) {
            return Err(JsError::new_loading_message(
                name,
                "native.mdx.v1 module loading is detached",
            ));
        }
        match name {
            JSX_RUNTIME_MODULE => Module::declare(ctx.clone(), name, JSX_RUNTIME_SOURCE),
            PROVIDER_MODULE => Module::declare(ctx.clone(), name, PROVIDER_SOURCE),
            _ => Err(JsError::new_loading_message(
                name,
                "module is not binary-owned",
            )),
        }
    }
}

fn classify_runtime_failure(message: &str) -> Failure {
    if message.contains("NativeResourceLimit:output_nodes") {
        return limit_failure("output_nodes", MAX_TREE_NODES);
    }
    let lower = message.to_ascii_lowercase();
    if lower.contains("out of memory") || lower.contains("allocation failed") {
        return Failure::new(
            "mdx_resource_limit_exceeded",
            "execute",
            "MDX execution exceeded the QuickJS heap limit",
        )
        .detail("limit", "quickjs_heap_bytes")
        .detail("maximum", 67_108_864u64);
    }
    if lower.contains("stack overflow")
        || lower.contains("call stack")
        || lower.contains("recursion")
    {
        return Failure::new(
            "mdx_resource_limit_exceeded",
            "execute",
            "MDX execution exceeded the QuickJS stack limit",
        )
        .detail("limit", "quickjs_stack_bytes")
        .detail("maximum", 524_288u64);
    }
    let (code, public, rule) =
        if message.contains("NativeUnknownComponent") || message.contains("Expected component") {
            (
                "mdx_unknown_component",
                "MDX references an unsupported component",
                "component_allowlist",
            )
        } else if message.contains("NativeInterfaceIncompatible") {
            (
                "module_interface_incompatible",
                "a module value did not satisfy its declared typed ABI",
                "module_typed_boundary",
            )
        } else if message.contains("NativeCapabilityDenied") {
            (
                "mdx_capability_denied",
                "MDX attempted an unavailable capability",
                "ambient_authority",
            )
        } else if message.contains("NativeOutputInvalid") {
            (
                "mdx_output_invalid",
                "MDX produced an invalid safe-tree value",
                "safe_tree",
            )
        } else {
            (
                "mdx_runtime_failed",
                "MDX execution failed",
                "runtime_throw",
            )
        };
    // The original QuickJS string can contain a generated-module location or
    // stack. It is used only for this bounded classification and never leaves
    // the adapter diagnostic boundary.
    Failure::new(code, "execute", public).detail("rule", rule)
}

fn runtime_prelude(input_json: &str, contexts_json: &str, allow_functions: bool) -> String {
    // Parse data rather than embedding it as an object literal. Besides
    // preserving every JSON string exactly, this keeps keys such as
    // `__proto__` as ordinary own data properties.
    let encoded_input = serde_json::to_string(input_json).expect("input JSON string serialization");
    let encoded_contexts =
        serde_json::to_string(contexts_json).expect("module contexts JSON string serialization");
    let native_components = if allow_functions {
        V2_NATIVE_COMPONENTS
    } else {
        NATIVE_COMPONENTS
    };
    let components = INTRINSICS
        .iter()
        .chain(native_components.iter())
        .map(|name| format!("{name}:\"{name}\""))
        .collect::<Vec<_>>()
        .join(",");
    let origin_bindings = if allow_functions {
        r#"const originEnter = globalThis.__nativeOriginEnter;
const originCapture = globalThis.__nativeOriginCapture;
const originSelect = globalThis.__nativeOriginSelect;
const originClear = globalThis.__nativeOriginClear;
const originExit = globalThis.__nativeOriginExit;"#
    } else {
        ""
    };
    let origin_store = if allow_functions {
        "const originErrors = new M();"
    } else {
        "const origins = new M();"
    };
    let with_origin = if allow_functions {
        r#"const withOrigin = freeze((originKey, exportName, edgeKey, thunk) => {
  originEnter(originKey, exportName, edgeKey);
  try { return thunk(); }
  catch (error) {
    const tagged = error && (typeof error === "object" || typeof error === "function") ? error : new E("NativeModuleFailure");
    if (!mapHas(originErrors, tagged)) mapSet(originErrors, tagged, originCapture());
    originSelect(mapGet(originErrors, tagged));
    throw tagged;
  }
  finally { originExit(); }
});
const enterModule = freeze((originKey) => originEnter(originKey, "$module", undefined));
const exitModule = freeze(() => originExit());"#
    } else {
        r#"const withOrigin = freeze((originKey, exportName, edgeKey, thunk) => {
  try { return thunk(); }
  catch (error) {
    const tagged = error && (typeof error === "object" || typeof error === "function") ? error : new E("NativeModuleFailure");
    const prior = mapGet(origins, tagged);
    const chain = freeze([edgeKey, ...(prior && isArray(prior.import_chain) ? prior.import_chain : [])]);
    mapSet(origins, tagged, freeze({
      origin_key: prior && typeof prior.origin_key === "string" ? prior.origin_key : originKey,
      export: prior && typeof prior.export === "string" ? prior.export : exportName,
      import_chain: chain
    }));
    throw tagged;
  }
});"#
    };
    let origin_globals = if allow_functions {
        r#", "__nativeOriginEnter", "__nativeOriginCapture", "__nativeOriginSelect", "__nativeOriginClear", "__nativeOriginExit""#
    } else {
        ""
    };
    let invoke = if allow_functions {
        r#"const invoke = freeze((content) => {
  try { return J.stringify({ ok: true, encoded: serializeNode(content(props)) }); }
  catch (error) {
    if (error && (typeof error === "object" || typeof error === "function") && mapHas(originErrors, error)) originSelect(mapGet(originErrors, error));
    else originClear();
    return J.stringify({ ok: false, message: S(error && error.message || error) });
  }
});"#
    } else {
        r#"const invoke = freeze((content) => {
  try { return J.stringify({ ok: true, encoded: serializeNode(content(props)) }); }
  catch (error) { return J.stringify({ ok: false, message: S(error && error.message || error), origin: error && (typeof error === "object" || typeof error === "function") ? mapGet(origins, error) || null : null }); }
});"#
    };
    let bridge_origin = if allow_functions {
        ", enterModule, exitModule"
    } else {
        ""
    };
    r#"(() => {
"use strict";
const O = Object, A = Array, W = WeakSet, M = WeakMap, F = Function, R = Reflect, J = JSON, S = String, N = Number, E = Error;
const keys = O.keys, freeze = O.freeze, define = O.defineProperty;
const ownKeys = R.ownKeys, getProto = O.getPrototypeOf, descriptors = O.getOwnPropertyDescriptors;
const isArray = A.isArray;
const call = F.prototype.call;
const weakHas = call.bind(W.prototype.has);
const weakAdd = call.bind(W.prototype.add);
const mapHas = call.bind(M.prototype.has);
const mapGet = call.bind(M.prototype.get);
const mapSet = call.bind(M.prototype.set);
const arrayPush = call.bind(A.prototype.push);
__NATIVE_ORIGIN_BINDINGS__
const fail = (name, message) => { throw new E(name + ":" + message); };
const denyDynamicCode = freeze(function () { fail("NativeCapabilityDenied", "dynamic code"); });
const AsyncFunction = (async function () {}).constructor;
const GeneratorFunction = (function* () {}).constructor;
const AsyncGeneratorFunction = (async function* () {}).constructor;
for (const constructor of [F, AsyncFunction, GeneratorFunction, AsyncGeneratorFunction]) {
  define(constructor.prototype, "constructor", {
    value: denyDynamicCode, writable: false, configurable: false
  });
}
const input = J.parse(__NATIVE_INPUT_JSON__);
const contexts = J.parse(__NATIVE_CONTEXTS_JSON__);
const records = new W();
const writableRecords = new W();
const writableRecordIds = new Set();
let sawScopedRecordEnvelope = false;
for (const record of input.records) weakAdd(records, record);
function relationRows(envelope) {
  return envelope && envelope.version === "native.relation-envelope.v1" && envelope.relation && isArray(envelope.relation.rows)
    ? envelope.relation.rows : null;
}
const groupedCounts = new W();
function markGroupedCount(envelope) {
  if (envelope && typeof envelope === "object" && envelope.version === "native.grouped-count-envelope.v1") weakAdd(groupedCounts, envelope);
}
const nodes = new W();
const authorities = new W();
__NATIVE_ORIGIN_STORE__
function deepFreeze(value, seen = new W()) {
  if (value && typeof value === "object" && !weakHas(seen, value)) {
    weakAdd(seen, value);
    for (const key of keys(value)) deepFreeze(value[key], seen);
    freeze(value);
  }
  return value;
}
function assertData(value, seen = new W()) {
  if (value === null || value === undefined) return;
  const kind = typeof value;
  if (kind === "function" || kind === "symbol" || kind === "bigint") fail("NativeOutputInvalid", "non-data prop");
  if (kind !== "object") return;
  if (weakHas(nodes, value)) fail("NativeOutputInvalid", "node used as prop");
  if (typeof value.then === "function") fail("NativeOutputInvalid", "async value");
  if (weakHas(seen, value)) fail("NativeOutputInvalid", "cyclic value");
  weakAdd(seen, value);
  for (const key of keys(value)) assertData(value[key], seen);
}
function markAuthority(value, seen = new W()) {
  if (!value || typeof value !== "object" || weakHas(seen, value)) return;
  weakAdd(seen, value); weakAdd(authorities, value);
  for (const key of keys(value)) markAuthority(value[key], seen);
}
function cloneBoundary(value, seen = new W()) {
  if (value === null || value === undefined || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") { if (!N.isFinite(value)) fail("NativeInterfaceIncompatible", "non-finite number"); return value; }
  if (typeof value !== "object") fail("NativeInterfaceIncompatible", "non-data boundary value");
  if (weakHas(authorities, value) || weakHas(records, value) || weakHas(nodes, value)) fail("NativeCapabilityDenied", "authority crossed module boundary");
  if (weakHas(seen, value)) fail("NativeInterfaceIncompatible", "cyclic boundary value");
  weakAdd(seen, value);
  const proto = getProto(value);
  const array = isArray(value);
  if ((!array && proto !== O.prototype && proto !== null) || (array && proto !== A.prototype)) fail("NativeInterfaceIncompatible", "host object or proxy boundary value");
  const props = descriptors(value);
  const names = ownKeys(props);
  if (names.some((name) => typeof name !== "string")) fail("NativeInterfaceIncompatible", "symbol boundary key");
  const output = array ? [] : {};
  for (const name of names) {
    const descriptor = props[name];
    if (!("value" in descriptor) || descriptor.get || descriptor.set) fail("NativeInterfaceIncompatible", "accessor or proxy boundary value");
    if (array && name === "length") continue;
    output[name] = cloneBoundary(descriptor.value, seen);
  }
  return output;
}
function validateSchema(schema, value, path) {
  if (!schema || typeof schema !== "object" || isArray(schema)) fail("NativeInterfaceIncompatible", path + " schema");
  const type = schema.type;
  if (type === "string" && typeof value !== "string") fail("NativeInterfaceIncompatible", path + " string");
  else if (type === "number" && (typeof value !== "number" || !N.isFinite(value))) fail("NativeInterfaceIncompatible", path + " number");
  else if (type === "integer" && (typeof value !== "number" || !N.isInteger(value))) fail("NativeInterfaceIncompatible", path + " integer");
  else if (type === "boolean" && typeof value !== "boolean") fail("NativeInterfaceIncompatible", path + " boolean");
  else if (type === "null" && value !== null) fail("NativeInterfaceIncompatible", path + " null");
  else if (type === "array") {
    if (!isArray(value)) fail("NativeInterfaceIncompatible", path + " array");
    if (schema.items) for (let i = 0; i < value.length; i++) validateSchema(schema.items, value[i], path + "[" + i + "]");
  } else if (type === "object") {
    if (!value || typeof value !== "object" || isArray(value)) fail("NativeInterfaceIncompatible", path + " object");
    const shape = schema.properties || {};
    for (const name of keys(value)) if (!(name in shape)) fail("NativeInterfaceIncompatible", path + "." + name + " undeclared");
    for (const name of keys(shape)) {
      if (shape[name].required === true && !(name in value)) fail("NativeInterfaceIncompatible", path + "." + name + " required");
      if (name in value) validateSchema(shape[name], value[name], path + "." + name);
    }
  } else if (!["string","number","integer","boolean","null","array","object"].includes(type)) fail("NativeInterfaceIncompatible", path + " unsupported schema");
}
function cloneProps(schema, supplied) {
  const clean = cloneBoundary(supplied || {});
  for (const name of keys(clean)) if (!(name in schema)) fail("NativeInterfaceIncompatible", "props." + name + " undeclared");
  for (const name of keys(schema)) {
    if (schema[name].required === true && !(name in clean)) fail("NativeInterfaceIncompatible", "props." + name + " required");
    if (name in clean) validateSchema(schema[name], clean[name], "props." + name);
  }
  return deepFreeze(clean);
}
const allowed = freeze(new Set([__NATIVE_ALLOWED__]));
const components = freeze({__NATIVE_COMPONENTS__});
deepFreeze(input);
for (const context of O.values(contexts)) {
  if (context && context.inputs) for (const envelope of O.values(context.inputs)) {
    if (envelope && envelope.version === "native.collection-envelope.v1" && isArray(envelope.records)) {
      sawScopedRecordEnvelope = true;
      for (const record of envelope.records) {
        weakAdd(records, record); weakAdd(writableRecords, record);
        if (record && typeof record.id === "string") writableRecordIds.add(record.id);
      }
    }
    const rows = relationRows(envelope);
    if (rows) { sawScopedRecordEnvelope = true; for (const record of rows) weakAdd(records, record); }
    markGroupedCount(envelope);
  }
}
for (const record of input.records) {
  if (!sawScopedRecordEnvelope || writableRecordIds.has(record && record.id)) weakAdd(writableRecords, record);
}
markAuthority(contexts);
deepFreeze(contexts);
const abiComponent = freeze((fn, descriptor, props, context) => {
  if (typeof fn !== "function") fail("NativeInterfaceIncompatible", "component export");
  const result = fn(cloneProps(descriptor.props || {}, props), context);
  if (result && typeof result.then === "function") fail("NativeInterfaceIncompatible", "async component result");
  if (!result || typeof result !== "object" || !weakHas(nodes, result)) fail("NativeInterfaceIncompatible", "component result");
  return result;
});
const abiFunction = freeze((fn, descriptor, args, context) => {
  if (typeof fn !== "function" || !isArray(descriptor.args) || args.length !== descriptor.args.length) fail("NativeInterfaceIncompatible", "function arguments");
  const clean = args.map((arg, index) => { const value = cloneBoundary(arg); validateSchema(descriptor.args[index], value, "args[" + index + "]"); return deepFreeze(value); });
  const result = fn(...clean, context);
  if (result && typeof result.then === "function") fail("NativeInterfaceIncompatible", "async function result");
  const cloned = cloneBoundary(result);
  validateSchema(descriptor.result, cloned, "result");
  return deepFreeze(cloned);
});
const abiConstant = freeze((value, descriptor) => {
  const cloned = cloneBoundary(value);
  validateSchema(descriptor.result, cloned, "constant");
  return deepFreeze(cloned);
});
__NATIVE_WITH_ORIGIN__
function create(type, supplied, key) {
  if (__NATIVE_ALLOW_FUNCTIONS__ && typeof type === "function") return type(supplied || {});
  if (typeof type !== "string" || !allowed.has(type)) fail("NativeUnknownComponent", "unsupported component");
  if (key !== undefined) fail("NativeCapabilityDenied", "key");
  const props = supplied || {};
  const clean = {};
  for (const name of keys(props)) {
    if (name === "children") continue;
    // `class` is admissible in native.mdx.v2 only, and is rewritten to its
    // prefixed form by the Rust tree validator, which is the authority here.
    // `style` and `className` stay denied at every tier.
    //
    // No `id` prop is admitted, at any tier, and none is denied here either:
    // the prop allowlist in `validate_props` admits `id` on nothing, which is
    // the whole enforcement. Author id selectors are inert precisely because
    // no element the author can emit carries an author id: `css.rs` flags
    // `#foo` rather than rewriting it, and that is only sound while that
    // holds. Admitting `id` would turn every flagged id selector live, and
    // unprefixed, in one step. Do not add one without an id rewrite in
    // `css.rs` alongside it.
    if (name === "ref" || name === "key" || name === "dangerouslySetInnerHTML" || name === "style" || __NATIVE_CLASS_DENIAL__name === "className" || /^on/i.test(name)) fail("NativeCapabilityDenied", name);
    assertData(props[name]);
    clean[name] = props[name];
  }
  if (type === "RecordList" || type === "RecordTable") {
    if (!isArray(clean.records)) fail("NativeCapabilityDenied", "fabricated record");
    for (const record of clean.records) if (!weakHas(records, record)) fail("NativeCapabilityDenied", "fabricated record");
  }
  if ((type === "RecordCard" || type === "FacetControl" || type === "Field") && !weakHas(records, clean.record)) fail("NativeCapabilityDenied", "fabricated record");
  if (type === "FacetControl" && !weakHas(writableRecords, clean.record)) fail("NativeCapabilityDenied", "read-only record");
  if (type === "RecordCard" && clean.draggable === true && !weakHas(writableRecords, clean.record)) fail("NativeCapabilityDenied", "read-only record");
  if (type === "BarChart" && !weakHas(groupedCounts, clean.data)) fail("NativeCapabilityDenied", "fabricated grouped count");
  const children = [];
  const append = (child) => {
    if (isArray(child)) { for (const item of child) append(item); return; }
    if (child === undefined || child === null || child === false || child === true) return;
    if (typeof child === "object" && !weakHas(nodes, child)) fail("NativeOutputInvalid", "untrusted object child");
    if (!(["string", "number", "object"].includes(typeof child))) fail("NativeOutputInvalid", "non-data child");
    arrayPush(children, child);
  };
  append(props.children);
  deepFreeze(clean);
  freeze(children);
  const node = { type, props: clean, children };
  weakAdd(nodes, node);
  return deepFreeze(node);
}
function serializeNode(value, seen = new W(), state = { count: 0 }) {
  if (!value || typeof value !== "object" || !weakHas(nodes, value)) fail("NativeOutputInvalid", "untrusted root or child node");
  if (weakHas(seen, value)) fail("NativeOutputInvalid", "cyclic node");
  weakAdd(seen, value);
  // Enforce the output quota at the bridge boundary before unnecessary JSON serialization.
  state.count += 1;
  if (state.count > __NATIVE_MAX_TREE_NODES__) fail("NativeResourceLimit", "output_nodes");
  for (const child of value.children) if (typeof child === "object") serializeNode(child, seen, state);
  const encoded = J.stringify(value);
  if (typeof encoded !== "string") fail("NativeOutputInvalid", "root");
  return encoded;
}
Math.random = () => fail("NativeCapabilityDenied", "random");
for (const name of [
  "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "process", "require", "console",
  "Date", "performance", "setTimeout", "setInterval", "queueMicrotask", "crypto",
  "Promise", "window", "document", "navigator", "location", "localStorage", "sessionStorage",
  "indexedDB", "caches", "BroadcastChannel", "Worker", "SharedWorker", "WebAssembly", "Intl"__NATIVE_ORIGIN_GLOBALS__
]) {
  define(globalThis, name, { value: undefined, writable: false, configurable: false });
}
for (const value of [O, O.prototype, A, A.prototype, W, W.prototype, M, M.prototype, F, F.prototype, AsyncFunction, AsyncFunction.prototype, GeneratorFunction, GeneratorFunction.prototype, AsyncGeneratorFunction, AsyncGeneratorFunction.prototype, R, J, S, S.prototype, N, N.prototype, E, E.prototype, Math, Set, Set.prototype]) freeze(value);
for (const [name, value] of [["Object", O], ["Array", A], ["WeakSet", W], ["WeakMap", M], ["Function", denyDynamicCode], ["eval", denyDynamicCode], ["Reflect", R], ["JSON", J], ["String", S], ["Number", N], ["Error", E], ["Math", Math]]) {
  define(globalThis, name, { value, writable: false, configurable: false });
}
const props = deepFreeze({ input });
__NATIVE_INVOKE__
define(globalThis, "__nativeBridge", {
  value: deepFreeze({ Fragment: "Fragment", jsx: create, jsxs: create, components, props, invoke,
    context: (key) => contexts[key] || fail("NativeCapabilityDenied", "module context"),
    abiComponent, abiFunction, abiConstant, withOrigin__NATIVE_BRIDGE_ORIGIN__ }),
  writable: false,
  configurable: false
});
})()"#
        .replace(
            "__NATIVE_ALLOWED__",
            &INTRINSICS
                .iter()
                .chain(native_components.iter())
                .map(|name| format!("\"{name}\""))
                .collect::<Vec<_>>()
                .join(","),
        )
        .replace("__NATIVE_COMPONENTS__", &components)
        .replace("__NATIVE_ORIGIN_BINDINGS__", origin_bindings)
        .replace("__NATIVE_ORIGIN_STORE__", origin_store)
        .replace("__NATIVE_WITH_ORIGIN__", with_origin)
        .replace("__NATIVE_ORIGIN_GLOBALS__", origin_globals)
        .replace("__NATIVE_INVOKE__", invoke)
        .replace("__NATIVE_BRIDGE_ORIGIN__", bridge_origin)
        .replace("__NATIVE_ALLOW_FUNCTIONS__", if allow_functions { "true" } else { "false" })
        .replace(
            "__NATIVE_CLASS_DENIAL__",
            if allow_functions { "" } else { "name === \"class\" || " },
        )
        .replace("__NATIVE_CONTEXTS_JSON__", &encoded_contexts)
        .replace("__NATIVE_MAX_TREE_NODES__", &MAX_TREE_NODES.to_string())
        // Input is substituted last so user-controlled strings that happen to
        // contain one of the binary template sentinels remain exact data.
        .replace("__NATIVE_INPUT_JSON__", &encoded_input)
}

pub fn validate_tree(tree: &mut Value, input: &Value) -> Result<usize, Failure> {
    validate_tree_profile(tree, input, None, false)
}

pub fn validate_v2_tree(tree: &mut Value, input: &Value) -> Result<usize, Failure> {
    validate_tree_profile(tree, input, None, true)
}

/// Validates a v2 safe tree against both its authored root input and the exact
/// scoped module contexts supplied by the host.
///
/// Grouped-count authority lives only in `contexts`: the root context contains
/// root-granted ports, and each module wrapper receives only the ports granted
/// to that exact release. Keeping these values out of the authored global
/// input prevents root source from borrowing a child module's `input.read`
/// grant while still letting a child return an authenticated chart node.
pub fn validate_v2_tree_with_contexts(
    tree: &mut Value,
    input: &Value,
    contexts: &Value,
) -> Result<usize, Failure> {
    validate_tree_profile(tree, input, Some(contexts), true)
}

fn validate_tree_profile(
    tree: &mut Value,
    input: &Value,
    contexts: Option<&Value>,
    writable_v2: bool,
) -> Result<usize, Failure> {
    if !tree.is_object() {
        return Err(output_failure(
            "safe-tree root must be a bridge-created node",
        ));
    }
    let canonical = CanonicalInput::new(input, contexts);
    let mut nodes = 0usize;
    validate_value(tree, 0, &mut nodes, &canonical, writable_v2, false, None)?;
    Ok(nodes)
}

/// The artifact's input records, indexed for identity checks, alongside the
/// set of facet keys any of them carries with a scalar value.
///
/// The key set is built once per tree because a RecordCard is instantiated per
/// record: checking each card's `fields` by scanning every input record would
/// be quadratic in a collection of up to 10,000, and this validation pass runs
/// after QuickJS with none of the interrupt or deadline budget behind it.
struct CanonicalInput<'a> {
    records: BTreeMap<&'a str, &'a Value>,
    writable_records: BTreeMap<&'a str, &'a Value>,
    scalar_facet_keys: BTreeSet<&'a str>,
    grouped_counts: Vec<&'a Value>,
}

fn context_record_rows(envelope: &Value) -> Option<&Vec<Value>> {
    if envelope.get("version").and_then(Value::as_str) == Some(RELATION_ENVELOPE_VERSION) {
        envelope.pointer("/relation/rows").and_then(Value::as_array)
    } else {
        envelope.get("records").and_then(Value::as_array)
    }
}

impl<'a> CanonicalInput<'a> {
    fn new(input: &'a Value, contexts: Option<&'a Value>) -> Self {
        let mut records = BTreeMap::new();
        let mut writable_records = BTreeMap::new();
        let mut scalar_facet_keys = BTreeSet::new();
        let context_envelopes = contexts
            .and_then(Value::as_object)
            .into_iter()
            .flat_map(Map::values)
            .flat_map(|context| {
                context
                    .get("inputs")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flat_map(Map::values)
            })
            .collect::<Vec<_>>();
        let saw_scoped_record_envelope = context_envelopes.iter().any(|envelope| {
            matches!(
                envelope.get("version").and_then(Value::as_str),
                Some("native.collection-envelope.v1") | Some(RELATION_ENVELOPE_VERSION)
            )
        });
        let grouped_counts = context_envelopes
            .iter()
            .copied()
            .filter(|value| {
                value.get("version").and_then(Value::as_str)
                    == Some("native.grouped-count-envelope.v1")
            })
            .collect();
        for record in input
            .get("records")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(
                context_envelopes
                    .iter()
                    .flat_map(|envelope| context_record_rows(envelope).into_iter().flatten()),
            )
        {
            let Some(id) = record.get("id").and_then(Value::as_str) else {
                continue;
            };
            records.insert(id, record);
            let facets = record.get("facets").and_then(Value::as_object);
            for (key, value) in facets.into_iter().flatten() {
                if matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)) {
                    scalar_facet_keys.insert(key.as_str());
                }
            }
        }
        for record in context_envelopes
            .iter()
            .filter(|envelope| {
                envelope.get("version").and_then(Value::as_str)
                    == Some("native.collection-envelope.v1")
            })
            .flat_map(|envelope| {
                envelope
                    .get("records")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
            })
        {
            if let Some(id) = record.get("id").and_then(Value::as_str) {
                writable_records.insert(id, record);
            }
        }
        if !saw_scoped_record_envelope {
            for record in input
                .get("records")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(id) = record.get("id").and_then(Value::as_str) {
                    writable_records.insert(id, record);
                }
            }
        }
        Self {
            records,
            writable_records,
            scalar_facet_keys,
            grouped_counts,
        }
    }

    fn carries(&self, field: &str) -> bool {
        RECORD_FIELDS.contains(&field) || self.scalar_facet_keys.contains(field)
    }
}

fn validate_value(
    value: &mut Value,
    depth: usize,
    nodes: &mut usize,
    canonical: &CanonicalInput,
    writable_v2: bool,
    inside_drop_target: bool,
    parent_type: Option<&str>,
) -> Result<(), Failure> {
    if depth > MAX_TREE_DEPTH {
        return Err(limit_failure("output_depth", MAX_TREE_DEPTH));
    }
    match value {
        Value::Null | Value::String(_) | Value::Number(_) => Ok(()),
        Value::Bool(_) => Err(output_failure(
            "boolean safe-tree children are not supported",
        )),
        Value::Array(values) => {
            for child in values {
                validate_value(
                    child,
                    depth + 1,
                    nodes,
                    canonical,
                    writable_v2,
                    inside_drop_target,
                    parent_type,
                )?;
            }
            Ok(())
        }
        Value::Object(node) => {
            *nodes += 1;
            if *nodes > MAX_TREE_NODES {
                return Err(limit_failure("output_nodes", MAX_TREE_NODES));
            }
            let node_type = node
                .get("type")
                .and_then(Value::as_str)
                .ok_or_else(|| output_failure("safe-tree nodes require a string type"))?
                .to_owned();
            let native_components = if writable_v2 {
                V2_NATIVE_COMPONENTS
            } else {
                NATIVE_COMPONENTS
            };
            if !INTRINSICS.contains(&node_type.as_str())
                && !native_components.contains(&node_type.as_str())
            {
                return Err(Failure::new(
                    "mdx_unknown_component",
                    "output",
                    format!(
                        "component '{node_type}' is not in {}",
                        if writable_v2 {
                            V2_COMPONENT_POLICY
                        } else {
                            COMPONENT_POLICY
                        }
                    ),
                )
                .detail("component", node_type.to_string()));
            }
            // Nested DropTargets are forbidden. One drop gesture on the inner
            // target also fires the outer one, so a single gesture would
            // commit two facet writes.
            //
            // The rendered tree is where this rule has to be real. The
            // native.mdx.v2 compiler refuses the same shape in authored JSX
            // (`drop_target_not_nested` in `mdx_v2.rs`), which is the earlier
            // and friendlier error, but it can only see the JSX a source
            // writes literally — a DropTarget returned by a helper component
            // or an imported module reaches the tree unseen. This check runs
            // over what was actually produced, so composition cannot evade it.
            //
            // The rule stops at DropTarget deliberately. A FacetControl inside
            // a DropTarget is legitimate: it commits on change, and a drop
            // gesture cannot also fire a change handler, so that nesting still
            // yields one write per gesture from two distinct gestures.
            if writable_v2 && inside_drop_target && node_type == "DropTarget" {
                return Err(Failure::new(
                    "mdx_policy_violation",
                    "output",
                    "a DropTarget may not appear inside another DropTarget: one drop gesture would commit two facet writes",
                )
                .detail("rule", "drop_target_not_nested"));
            }
            if writable_v2 && node_type == "PlacementPreview" && parent_type != Some("DropTarget") {
                return Err(Failure::new(
                    "mdx_policy_violation",
                    "output",
                    "a PlacementPreview must be a direct child of DropTarget",
                )
                .detail("rule", "placement_preview_direct_child"));
            }
            if node
                .keys()
                .any(|key| !matches!(key.as_str(), "type" | "props" | "children"))
            {
                return Err(output_failure("safe-tree node has an unknown field"));
            }
            if node.get("props").and_then(Value::as_object).is_none() {
                return Err(output_failure("safe-tree node props must be an object"));
            }
            // Validation may replace accepted absolute links with the one
            // canonical URL string that the browser is allowed to consume.
            let props = node
                .get_mut("props")
                .and_then(Value::as_object_mut)
                .expect("safe-tree props were just validated as an object");
            validate_props(&node_type, props, canonical, writable_v2)?;
            let children = node
                .get_mut("children")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| output_failure("safe-tree node children must be an array"))?;
            if matches!(
                node_type.as_str(),
                "hr" | "br" | "img" | "BarChart" | "RecordCreate"
            ) && !children.is_empty()
            {
                return Err(output_failure(format!(
                    "{node_type} is a void element and cannot have children"
                )));
            }
            if matches!(node_type.as_str(), "Badge" | "EmptyState")
                && children
                    .iter()
                    .any(|child| !matches!(child, Value::String(_) | Value::Number(_)))
            {
                return Err(output_failure(format!(
                    "{node_type} accepts scalar children only"
                )));
            }
            if node_type == "PlacementPreview" && children.is_empty() {
                return Err(Failure::new(
                    "mdx_output_invalid",
                    "output",
                    "PlacementPreview must contain at least one child",
                )
                .detail("rule", "placement_preview_nonempty"));
            }
            if node_type == "DropTarget" {
                let mut preview_records = BTreeSet::new();
                for child in children.iter() {
                    collect_direct_placement_previews(child, &mut preview_records)?;
                }
            }
            for child in children {
                validate_value(
                    child,
                    depth + 1,
                    nodes,
                    canonical,
                    writable_v2,
                    // A DropTarget makes its whole subtree a drop region, not
                    // just its direct children, because the browser's drop
                    // event bubbles through whatever sits between.
                    inside_drop_target || node_type == "DropTarget",
                    Some(&node_type),
                )?;
            }
            Ok(())
        }
    }
}

/// Arrays are transparent safe-tree children: JSX maps are flattened by the
/// bridge today, while the Rust validator also accepts an equivalent decoded
/// array defensively. Scan through arrays but stop at component nodes so the
/// direct-child rule and duplicate rule describe the same structural edge.
fn collect_direct_placement_previews<'a>(
    value: &'a Value,
    records: &mut BTreeSet<&'a str>,
) -> Result<(), Failure> {
    if let Some(values) = value.as_array() {
        for child in values {
            collect_direct_placement_previews(child, records)?;
        }
        return Ok(());
    }
    if value.get("type").and_then(Value::as_str) != Some("PlacementPreview") {
        return Ok(());
    }
    let Some(record_id) = value
        .get("props")
        .and_then(Value::as_object)
        .and_then(|props| props.get("recordId"))
        .and_then(Value::as_str)
    else {
        return Ok(());
    };
    if records.insert(record_id) {
        return Ok(());
    }
    Err(Failure::new(
        "mdx_policy_violation",
        "output",
        format!("DropTarget declares more than one PlacementPreview for record '{record_id}'"),
    )
    .detail("rule", "placement_preview_unique_record")
    .detail("record_id", record_id.to_owned()))
}

fn validate_props(
    node_type: &str,
    props: &mut Map<String, Value>,
    canonical: &CanonicalInput,
    writable_v2: bool,
) -> Result<(), Failure> {
    let allowed: &[&str] = match node_type {
        "a" => &["href"],
        "img" => &["src", "alt"],
        "Stack" => &["gap"],
        "Grid" => &["columns", "gap"],
        "Callout" => &["title", "tone"],
        "Badge" => &["tone"],
        "Metric" => &["label", "value", "detail"],
        "BarChart" if writable_v2 => &["label", "data"],
        "RecordList" => &["records", "empty"],
        "RecordTable" => &["records", "columns"],
        "RecordCard" if writable_v2 => &["record", "fields", "draggable"],
        "RecordCard" => &["record", "fields"],
        "FacetControl" if writable_v2 => &["entry", "record"],
        "DropTarget" if writable_v2 => &["entry"],
        "PlacementPreview" if writable_v2 => &["recordId"],
        "RecordCreate" if writable_v2 => &["entry"],
        "Field" => &["record", "field"],
        "EmptyState" => &["title"],
        _ if INTRINSICS.contains(&node_type) => &[],
        _ => return Err(output_failure("unknown component")),
    };
    // `class` is admitted on every native component and intrinsic — and only
    // in native.mdx.v2, where author CSS exists to make it mean something. It
    // is not in any per-component allowlist because it is universal, so it is
    // skipped here and handled by `prefixed_class` below. `style` and
    // `className` are in no allowlist at all and therefore stay denied: an
    // inline style declaration is unvalidatable CSS, and `className` would be
    // a second, unprefixed spelling of the same attribute.
    //
    // `id` is admitted on nothing, deliberately. `css.rs` flags an author
    // `#foo` selector rather than rewriting it, which is only safe while no
    // element the author can emit carries an author id. Admitting `id` here
    // would make every flagged id selector live and unprefixed in one step,
    // and unprefixed means it can collide with a host id. Any future `id`
    // admission has to land together with an id-selector rewrite in `css.rs`.
    for name in props.keys() {
        if writable_v2 && name == "class" {
            if matches!(node_type, "BarChart" | "RecordCreate") {
                let rule = if node_type == "BarChart" {
                    "bar_chart_closed_surface"
                } else {
                    "record_create_closed_surface"
                };
                return Err(Failure::new(
                    "mdx_output_invalid",
                    "output",
                    format!("{node_type} is a closed semantic primitive and does not accept author styling"),
                )
                .detail("rule", rule)
                .detail("component", node_type.to_string())
                .detail("prop", name.clone()));
            }
            continue;
        }
        if !allowed.contains(&name.as_str()) {
            return Err(Failure::new(
                "mdx_output_invalid",
                "output",
                format!("prop '{name}' is not allowed on {node_type}"),
            )
            .detail("rule", "component_prop_allowlist")
            .detail("component", node_type.to_string())
            .detail("prop", name.clone()));
        }
    }
    if writable_v2 {
        if let Some(value) = props.get("class") {
            // `Fragment` is an intrinsic, so `class` is admitted and prefixed
            // like anywhere else — and then renders no element at all, so the
            // browser silently drops it. The author's rule never matches and
            // nothing anywhere says why. Validation is the only layer that can
            // tell them, so it does, rather than accepting a prop it knows to
            // be inert.
            if matches!(node_type, "Fragment" | "PlacementPreview") {
                let rule = if node_type == "Fragment" {
                    "class_on_fragment"
                } else {
                    "class_on_placement_preview"
                };
                return Err(Failure::new(
                    "mdx_output_invalid",
                    "output",
                    format!(
                        "prop 'class' has no effect on {node_type}, which renders no element; move it to the element you want to style"
                    ),
                )
                .detail("rule", rule)
                .detail("component", node_type.to_string())
                .detail("prop", "class"));
            }
            let rewritten = prefixed_class(value, node_type)?;
            props.insert("class".into(), Value::String(rewritten));
        }
    }
    match node_type {
        "a" => {
            let canonical = validate_href(required_string(props, "href")?)?;
            props.insert("href".into(), Value::String(canonical));
        }
        "img" => {
            let alt = required_string(props, "alt")?;
            if alt.trim().is_empty() {
                return Err(output_failure("img alt must be non-blank"));
            }
            validate_image(required_string(props, "src")?)?;
        }
        "Stack" => enum_number(props, "gap", &[1, 2, 3, 4], true)?,
        "Grid" => {
            enum_number(props, "columns", &[1, 2, 3, 4], true)?;
            enum_number(props, "gap", &[1, 2, 3, 4], true)?;
        }
        "Callout" => enum_string(
            props,
            "tone",
            &["neutral", "info", "success", "warning", "danger"],
            true,
        )
        .and_then(|_| optional_string(props, "title"))?,
        "Badge" => enum_string(
            props,
            "tone",
            &["neutral", "info", "success", "warning", "danger"],
            true,
        )?,
        "Metric" => {
            required_scalar(props, "label")?;
            required_scalar(props, "value")?;
            optional_scalar(props, "detail")?;
        }
        "BarChart" if writable_v2 => canonical_grouped_count_chart(props, canonical)?,
        "RecordList" => {
            canonical_record_list(props.get("records"), &canonical.records)?;
            optional_scalar(props, "empty")?;
        }
        "RecordTable" => {
            canonical_record_list(props.get("records"), &canonical.records)?;
            fields(props.get("columns"), true)?;
            validate_record_fields(props.get("records"), props.get("columns"))?;
        }
        "RecordCard" => {
            canonical_record(props.get("record"), &canonical.records)?;
            fields(props.get("fields"), false)?;
            if writable_v2 {
                optional_bool(props, "draggable")?;
                if props.get("draggable").and_then(Value::as_bool) == Some(true) {
                    canonical_record(props.get("record"), &canonical.writable_records)?;
                }
            }
            if props.contains_key("fields") {
                // Every canonical input record, not just the one this card
                // is bound to. Cards are authored over heterogeneous sets — a
                // folder holds tasks, notes and decisions, and an open facet
                // is exactly the kind that will not be uniformly present — so
                // checking a card against its own record alone let one absence
                // refuse the whole artifact, where the same facet as a
                // RecordTable column has always rendered and left the cell
                // blank. The renderer blanks an absent field either way.
                validate_fields_present(props.get("fields"), |field| canonical.carries(field))?;
            }
        }
        "FacetControl" if writable_v2 => {
            canonical_record(props.get("record"), &canonical.writable_records)?;
            required_non_blank_string(props, "entry")?;
        }
        "DropTarget" if writable_v2 => required_non_blank_string(props, "entry")?,
        "RecordCreate" if writable_v2 => required_non_blank_string(props, "entry")?,
        "PlacementPreview" if writable_v2 => {
            let record_id = required_string(props, "recordId")?;
            if record_id.trim().is_empty() {
                return Err(output_failure("prop 'recordId' must be non-blank"));
            }
            if !canonical.writable_records.contains_key(record_id) {
                return Err(Failure::new(
                    "mdx_capability_denied",
                    "output",
                    "PlacementPreview received a record id outside the resolved input",
                )
                .detail("rule", "canonical_record_identity"));
            }
        }
        "Field" => {
            canonical_record(props.get("record"), &canonical.records)?;
            let field = required_string(props, "field")?;
            if field.trim().is_empty() || !record_has_field(&props["record"], field) {
                return Err(output_failure(
                    "Field field must name a scalar record field or facet",
                ));
            }
        }
        "EmptyState" => optional_string(props, "title")?,
        _ => {}
    }
    Ok(())
}

/// Rewrites an author `class` prop into its prefixed form.
///
/// The browser renders the result verbatim, so this is the DOM half of the
/// same rewrite `css.rs` performs on class selectors: `class="card"` and
/// `.card { }` both become `nsa-card`, and neither can name a host class.
///
/// The accepted token grammar is exactly the identifier grammar `css.rs`
/// tokenizes a class selector with, so a name that can be written in the
/// stylesheet can be written here and vice versa.
fn prefixed_class(value: &Value, node_type: &str) -> Result<String, Failure> {
    let reject = |rule: &'static str, message: String| {
        Failure::new("mdx_output_invalid", "output", message)
            .detail("rule", rule)
            .detail("component", node_type.to_string())
    };
    let Some(value) = value.as_str() else {
        return Err(reject(
            "author_class_grammar",
            "prop 'class' must be a string".into(),
        ));
    };
    let mut names = Vec::new();
    for token in value.split_ascii_whitespace() {
        if token.len() > MAX_AUTHOR_CLASS_BYTES {
            return Err(reject(
                "author_class_grammar",
                format!("class name '{token}' exceeds {MAX_AUTHOR_CLASS_BYTES} bytes"),
            ));
        }
        let mut chars = token.chars();
        let head = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '-' || (c as u32) >= 0x80);
        let rest =
            chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || (c as u32) >= 0x80);
        if !head || !rest {
            return Err(reject(
                "author_class_grammar",
                format!("class name '{token}' is not a CSS identifier"),
            ));
        }
        names.push(format!("{AUTHOR_CLASS_PREFIX}{token}"));
        if names.len() > MAX_AUTHOR_CLASSES {
            return Err(reject(
                "author_class_grammar",
                format!("an element may carry at most {MAX_AUTHOR_CLASSES} classes"),
            ));
        }
    }
    Ok(names.join(" "))
}

fn required_string<'a>(props: &'a Map<String, Value>, name: &str) -> Result<&'a str, Failure> {
    props
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| output_failure(format!("prop '{name}' must be a string")))
}

fn required_scalar(props: &Map<String, Value>, name: &str) -> Result<(), Failure> {
    match props.get(name) {
        Some(Value::String(_) | Value::Number(_) | Value::Bool(_)) => Ok(()),
        _ => Err(output_failure(format!("prop '{name}' must be a scalar"))),
    }
}

fn optional_scalar(props: &Map<String, Value>, name: &str) -> Result<(), Failure> {
    match props.get(name) {
        None | Some(Value::Null | Value::String(_) | Value::Number(_) | Value::Bool(_)) => Ok(()),
        _ => Err(output_failure(format!("prop '{name}' must be a scalar"))),
    }
}

fn optional_string(props: &Map<String, Value>, name: &str) -> Result<(), Failure> {
    match props.get(name) {
        None | Some(Value::Null | Value::String(_)) => Ok(()),
        _ => Err(output_failure(format!("prop '{name}' must be a string"))),
    }
}

fn required_non_blank_string(props: &Map<String, Value>, name: &str) -> Result<(), Failure> {
    if required_string(props, name)?.trim().is_empty() {
        return Err(output_failure(format!("prop '{name}' must be non-blank")));
    }
    Ok(())
}

fn optional_bool(props: &Map<String, Value>, name: &str) -> Result<(), Failure> {
    match props.get(name) {
        None | Some(Value::Bool(_)) => Ok(()),
        _ => Err(output_failure(format!("prop '{name}' must be a boolean"))),
    }
}

fn enum_number(
    props: &Map<String, Value>,
    name: &str,
    allowed: &[i64],
    required: bool,
) -> Result<(), Failure> {
    match props.get(name).and_then(Value::as_i64) {
        Some(value) if allowed.contains(&value) => Ok(()),
        None if !required && !props.contains_key(name) => Ok(()),
        _ => Err(output_failure(format!(
            "prop '{name}' is outside its allowed values"
        ))),
    }
}

fn enum_string(
    props: &Map<String, Value>,
    name: &str,
    allowed: &[&str],
    required: bool,
) -> Result<(), Failure> {
    match props.get(name).and_then(Value::as_str) {
        Some(value) if allowed.contains(&value) => Ok(()),
        None if !required && !props.contains_key(name) => Ok(()),
        _ => Err(output_failure(format!(
            "prop '{name}' is outside its allowed values"
        ))),
    }
}

fn canonical_record_list(
    value: Option<&Value>,
    canonical_records: &BTreeMap<&str, &Value>,
) -> Result<(), Failure> {
    let records = value
        .and_then(Value::as_array)
        .ok_or_else(|| output_failure("records must be an array"))?;
    for record in records {
        canonical_record(Some(record), canonical_records)?;
    }
    Ok(())
}

fn canonical_record(
    value: Option<&Value>,
    canonical_records: &BTreeMap<&str, &Value>,
) -> Result<(), Failure> {
    let value = value.ok_or_else(|| output_failure("record prop is not an input record"))?;
    let id = value
        .as_object()
        .and_then(|record| record.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| output_failure("record prop is not an input record"))?;
    if canonical_records.get(id).copied() != Some(value) {
        return Err(Failure::new(
            "mdx_capability_denied",
            "output",
            "record component received a fabricated record",
        )
        .detail("rule", "canonical_record_identity"));
    }
    Ok(())
}

/// Replaces an authenticated grouped-count envelope with the only chart data
/// the browser is allowed to see. QuickJS proves object identity before the
/// value crosses the JSON bridge; this pass independently proves that the
/// value is one of the host inputs and that its closed, digest-bound payload
/// still satisfies the grouped-count contract.
fn canonical_grouped_count_chart(
    props: &mut Map<String, Value>,
    canonical: &CanonicalInput,
) -> Result<(), Failure> {
    let label = props
        .get("label")
        .and_then(Value::as_str)
        .ok_or_else(|| output_failure("BarChart label must be a string"))?;
    if label.trim().is_empty()
        || label.len() > MAX_CHART_LABEL_BYTES
        || label.chars().any(char::is_control)
    {
        return Err(output_failure(format!(
            "BarChart label must be non-blank, control-free, and at most {MAX_CHART_LABEL_BYTES} bytes"
        )));
    }

    let data = props
        .get("data")
        .ok_or_else(|| output_failure("BarChart data must be a grouped-count input"))?;
    if !canonical.grouped_counts.contains(&data) {
        return Err(Failure::new(
            "mdx_capability_denied",
            "output",
            "BarChart received a fabricated grouped-count value",
        )
        .detail("rule", "canonical_grouped_count_identity"));
    }
    let envelope = exact_object(
        data,
        &[
            "version",
            "collection",
            "projection",
            "total",
            "buckets",
            "buckets_sha256",
        ],
        "grouped-count envelope",
    )?;
    exact_string(
        envelope.get("version"),
        "native.grouped-count-envelope.v1",
        "grouped-count envelope version",
    )?;

    let collection = exact_object(
        envelope.get("collection").expect("closed envelope key"),
        &["id", "kind"],
        "grouped-count collection",
    )?;
    for field in ["id", "kind"] {
        let value = collection
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                output_failure(format!("grouped-count collection {field} must be a string"))
            })?;
        if value.trim().is_empty()
            || value.len() > MAX_GROUPED_COUNT_KEY_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(output_failure(format!(
                "grouped-count collection {field} is outside its allowed string bounds"
            )));
        }
    }

    let projection = exact_object(
        envelope.get("projection").expect("closed envelope key"),
        &["kind", "axis", "binding_event_seq", "order"],
        "grouped-count projection",
    )?;
    exact_string(
        projection.get("kind"),
        "grouped_count",
        "grouped-count projection kind",
    )?;
    exact_string(
        projection.get("order"),
        "count_desc_key_asc_null_first",
        "grouped-count projection order",
    )?;
    let axis_value = projection.get("axis").expect("closed projection key");
    match axis_value.get("kind").and_then(Value::as_str) {
        Some("record_field") => {
            let axis = exact_object(axis_value, &["kind", "field"], "grouped-count axis")?;
            exact_string(axis.get("field"), "kind", "grouped-count axis field")?;
        }
        Some("facet") => {
            let axis = exact_object(axis_value, &["kind", "key"], "grouped-count axis")?;
            let key = axis
                .get("key")
                .and_then(Value::as_str)
                .ok_or_else(|| output_failure("grouped-count facet key must be a string"))?;
            if !super::mdx_v2::valid_facet_key(key) {
                return Err(output_failure(format!(
                    "grouped-count facet key must be non-blank, control-free, and at most {} bytes",
                    super::mdx_v2::MAX_FACET_KEY_BYTES
                )));
            }
        }
        _ => {
            return Err(output_failure(
                "grouped-count axis kind must be record_field or facet",
            ));
        }
    }
    let binding_event_seq = projection
        .get("binding_event_seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            output_failure("grouped-count binding_event_seq must be a non-negative integer")
        })?;
    if binding_event_seq > 9_007_199_254_740_991 {
        return Err(output_failure(
            "grouped-count binding_event_seq exceeds the JSON safe-integer range",
        ));
    }

    let total = envelope
        .get("total")
        .and_then(Value::as_u64)
        .ok_or_else(|| output_failure("grouped-count total must be a non-negative integer"))?;
    if total > MAX_GROUPED_COUNT_TOTAL {
        return Err(limit_failure(
            "grouped_count_total",
            MAX_GROUPED_COUNT_TOTAL as usize,
        ));
    }
    let buckets = envelope
        .get("buckets")
        .and_then(Value::as_array)
        .ok_or_else(|| output_failure("grouped-count buckets must be an array"))?;
    if buckets.len() > MAX_GROUPED_COUNT_BUCKETS {
        return Err(limit_failure(
            "grouped_count_buckets",
            MAX_GROUPED_COUNT_BUCKETS,
        ));
    }

    let mut sum = 0u64;
    let mut previous: Option<(u64, Option<&str>)> = None;
    let mut keys = BTreeSet::new();
    for bucket in buckets {
        let bucket = exact_object(bucket, &["key", "count"], "grouped-count bucket")?;
        let key = match bucket.get("key") {
            Some(Value::Null) => None,
            Some(Value::String(value))
                if value.len() <= MAX_GROUPED_COUNT_KEY_BYTES
                    && !value.chars().any(char::is_control) =>
            {
                Some(value.as_str())
            }
            _ => {
                return Err(output_failure(format!(
                    "grouped-count bucket key must be null or a control-free string of at most {MAX_GROUPED_COUNT_KEY_BYTES} bytes"
                )))
            }
        };
        if !keys.insert(key) {
            return Err(output_failure("grouped-count bucket keys must be unique"));
        }
        let count = bucket.get("count").and_then(Value::as_u64).ok_or_else(|| {
            output_failure("grouped-count bucket count must be a positive integer")
        })?;
        if count == 0 {
            return Err(output_failure(
                "grouped-count buckets must omit zero-count categories",
            ));
        }
        if count > MAX_GROUPED_COUNT_TOTAL {
            return Err(limit_failure(
                "grouped_count_bucket_count",
                MAX_GROUPED_COUNT_TOTAL as usize,
            ));
        }
        sum = sum
            .checked_add(count)
            .ok_or_else(|| output_failure("grouped-count bucket sum overflowed"))?;
        if previous.is_some_and(|(previous_count, previous_key)| {
            count > previous_count || (count == previous_count && key <= previous_key)
        }) {
            return Err(output_failure(
                "grouped-count buckets must use count_desc_key_asc_null_first order",
            ));
        }
        previous = Some((count, key));
    }
    if sum != total {
        return Err(output_failure(
            "grouped-count total must equal the sum of bucket counts",
        ));
    }

    let digest = envelope
        .get("buckets_sha256")
        .and_then(Value::as_str)
        .ok_or_else(|| output_failure("grouped-count buckets_sha256 must be a string"))?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || digest != grouped_count_buckets_sha256(buckets)
    {
        return Err(output_failure(
            "grouped-count buckets_sha256 does not match the canonical buckets",
        ));
    }

    let canonical_buckets = buckets.clone();
    props.remove("data");
    props.insert("total".into(), Value::from(total));
    props.insert("buckets".into(), Value::Array(canonical_buckets));
    Ok(())
}

fn exact_object<'a>(
    value: &'a Value,
    keys: &[&str],
    subject: &str,
) -> Result<&'a Map<String, Value>, Failure> {
    let object = value
        .as_object()
        .ok_or_else(|| output_failure(format!("{subject} must be an object")))?;
    if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
        return Err(output_failure(format!(
            "{subject} must contain exactly its declared fields"
        )));
    }
    Ok(object)
}

fn exact_string(value: Option<&Value>, expected: &str, subject: &str) -> Result<(), Failure> {
    if value.and_then(Value::as_str) != Some(expected) {
        return Err(output_failure(format!("{subject} is unsupported")));
    }
    Ok(())
}

fn grouped_count_buckets_sha256(buckets: &[Value]) -> String {
    let mut canonical = Value::Array(buckets.to_vec());
    canonicalize(&mut canonical);
    sha256_hex(&serde_json::to_vec(&canonical).expect("canonical grouped-count buckets serialize"))
}

fn fields(value: Option<&Value>, required: bool) -> Result<(), Failure> {
    if value.is_none() && !required {
        return Ok(());
    }
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| output_failure("fields/columns must be an array"))?;
    if required && values.is_empty() {
        return Err(output_failure("columns must not be empty"));
    }
    for value in values {
        let field = value
            .as_str()
            .ok_or_else(|| output_failure("field names must be strings"))?;
        if field.trim().is_empty() {
            return Err(output_failure("field names must not be blank"));
        }
    }
    Ok(())
}

fn validate_record_fields(records: Option<&Value>, fields: Option<&Value>) -> Result<(), Failure> {
    let records = records
        .and_then(Value::as_array)
        .ok_or_else(|| output_failure("record field validation requires records"))?;
    validate_fields_present(fields, |field| {
        records.iter().any(|record| record_has_field(record, field))
    })
}

/// Admits a field carried by at least one record in the caller's scope; the
/// renderer blanks it for the rest. The scope differs by component, so the
/// failure says "in scope" rather than naming one: a RecordTable checks the
/// list bound to it, which may be a filtered subset, and a RecordCard checks
/// the whole canonical input set.
fn validate_fields_present(
    fields: Option<&Value>,
    mut carried: impl FnMut(&str) -> bool,
) -> Result<(), Failure> {
    let fields = fields
        .and_then(Value::as_array)
        .ok_or_else(|| output_failure("fields/columns must be an array"))?;
    for field in fields {
        let field = field
            .as_str()
            .ok_or_else(|| output_failure("field names must be strings"))?;
        if !RECORD_FIELDS.contains(&field) && !carried(field) {
            return Err(output_failure(format!(
                "field '{field}' is not a present scalar record field or facet on any record in scope"
            )));
        }
    }
    Ok(())
}

fn record_has_field(record: &Value, field: &str) -> bool {
    if RECORD_FIELDS.contains(&field) {
        return true;
    }
    record
        .get("facets")
        .and_then(Value::as_object)
        .and_then(|facets| facets.get(field))
        .is_some_and(|value| matches!(value, Value::String(_) | Value::Number(_) | Value::Bool(_)))
}

fn validate_href(href: &str) -> Result<String, Failure> {
    if href.chars().any(char::is_control) || href.starts_with("//") {
        return Err(output_failure("link URL is not allowed"));
    }
    if href.starts_with('#') {
        return Ok(href.to_owned());
    }
    let url = Url::parse(href)
        .map_err(|_| output_failure("link must be a fragment or absolute http(s) URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(output_failure("link URL is not allowed"));
    }
    Ok(url.to_string())
}

fn validate_image(src: &str) -> Result<(), Failure> {
    let (header, payload) = src
        .split_once(',')
        .ok_or_else(|| output_failure("img src must be a raster data URL"))?;
    if !matches!(
        header,
        "data:image/png;base64"
            | "data:image/jpeg;base64"
            | "data:image/gif;base64"
            | "data:image/webp;base64"
    ) {
        return Err(output_failure("img src must be a base64 raster data URL"));
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(payload)
        .map_err(|_| output_failure("img src has invalid base64"))?;
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(limit_failure("data_image_decoded_bytes", MAX_IMAGE_BYTES));
    }
    let valid_signature = match header {
        "data:image/png;base64" => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "data:image/jpeg;base64" => bytes.starts_with(b"\xff\xd8\xff"),
        "data:image/gif;base64" => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        "data:image/webp;base64" => bytes.starts_with(b"RIFF") && bytes.get(8..12) == Some(b"WEBP"),
        _ => false,
    };
    if !valid_signature {
        return Err(output_failure(
            "img bytes do not match the declared raster type",
        ));
    }
    Ok(())
}

fn canonicalize(value: &mut Value) {
    match value {
        Value::Array(values) => values.iter_mut().for_each(canonicalize),
        Value::Object(object) => {
            for value in object.values_mut() {
                canonicalize(value);
            }
            let sorted = std::mem::take(object)
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            object.extend(sorted);
        }
        _ => {}
    }
}

fn cache_entry(key: &str, compiled: String) -> CacheEntry {
    CacheEntry {
        compiled_sha256: sha256_hex(compiled.as_bytes()),
        manifest_sha256: cache_manifest(key),
        compiled,
        last_used: 0,
    }
}

fn cache_lookup(key: &str, expected_manifest: &str) -> (Option<String>, bool) {
    let mut cache = cache().lock().expect("MDX cache lock poisoned");
    cache.clock = cache.clock.wrapping_add(1);
    let now = cache.clock;
    let Some(entry) = cache.entries.get(key).cloned() else {
        return (None, false);
    };
    if entry.manifest_sha256 != expected_manifest
        || sha256_hex(entry.compiled.as_bytes()) != entry.compiled_sha256
    {
        cache.entries.remove(key);
        cache.bytes = cache.bytes.saturating_sub(entry.compiled.len());
        return (None, true);
    }
    if let Some(stored) = cache.entries.get_mut(key) {
        stored.last_used = now;
    }
    (Some(entry.compiled), false)
}

fn cache_insert(key: String, mut entry: CacheEntry) {
    let mut cache = cache().lock().expect("MDX cache lock poisoned");
    cache.clock = cache.clock.wrapping_add(1);
    entry.last_used = cache.clock;
    if let Some(previous) = cache.entries.remove(&key) {
        cache.bytes = cache.bytes.saturating_sub(previous.compiled.len());
    }
    cache.bytes += entry.compiled.len();
    cache.entries.insert(key, entry);
    while cache.entries.len() > MAX_CACHE_ENTRIES || cache.bytes > MAX_CACHE_BYTES {
        let victim = cache
            .entries
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                (left.last_used, left_key.as_str()).cmp(&(right.last_used, right_key.as_str()))
            })
            .map(|(key, _)| key.clone())
            .expect("over-limit cache has an entry");
        if let Some(removed) = cache.entries.remove(&victim) {
            cache.bytes = cache.bytes.saturating_sub(removed.compiled.len());
        }
    }
}

fn cache_manifest(key: &str) -> String {
    sha256_hex(format!("{CACHE_NAMESPACE}\0{key}\0{ADAPTER_REVISION}").as_bytes())
}

fn cache_key(body_sha256: &str) -> String {
    let fields = [
        ("namespace", CACHE_NAMESPACE),
        ("body_sha256", body_sha256),
        ("runtime_id", RUNTIME_ID),
        ("compiler", "mdxjs@1.0.4"),
        ("compile_profile", COMPILE_PROFILE),
        ("component_policy", COMPONENT_POLICY),
        ("input_envelope", "native.artifact-input.v1"),
        ("executor", "rquickjs@0.11.0"),
        ("output", SAFE_TREE_VERSION),
        ("adapter_revision", ADAPTER_REVISION),
    ];
    let mut digest = Sha256::new();
    for (name, value) in fields {
        for part in [name.as_bytes(), value.as_bytes()] {
            digest.update((part.len() as u64).to_be_bytes());
            digest.update(part);
        }
    }
    hex::encode(digest.finalize())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn output_failure(message: impl Into<String>) -> Failure {
    Failure::new("mdx_output_invalid", "output", message)
}

fn limit_failure(limit: &'static str, maximum: usize) -> Failure {
    Failure::new(
        "mdx_resource_limit_exceeded",
        "output",
        format!("MDX output exceeded {limit}"),
    )
    .detail("limit", limit)
    .detail("maximum", maximum as u64)
}

fn bounded(value: &str, maximum: usize) -> String {
    value.chars().take(maximum).collect()
}

pub(crate) fn elapsed_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn parse_location(message: &str) -> Option<(u64, u64)> {
    let bytes = message.as_bytes();
    for start in 0..bytes.len() {
        if !bytes[start].is_ascii_digit() {
            continue;
        }
        let mut separator = start;
        while bytes.get(separator).is_some_and(u8::is_ascii_digit) {
            separator += 1;
        }
        if bytes.get(separator) != Some(&b':') {
            continue;
        }
        let column_start = separator + 1;
        let mut end = column_start;
        while bytes.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
        if end > column_start {
            let line = message[start..separator].parse().ok()?;
            let column = message[column_start..end].parse().ok()?;
            return Some((line, column));
        }
    }
    None
}

#[cfg(test)]
pub fn corrupt_cache_for(source: &str) {
    let key = cache_key(&sha256_hex(source.as_bytes()));
    let storage_key = format!("{}:{key}", sha256_hex(b"test/local"));
    if let Some(entry) = cache()
        .lock()
        .expect("cache lock")
        .entries
        .get_mut(&storage_key)
    {
        entry.compiled.push_str("corrupt");
    }
}

#[cfg(any(test, feature = "test-support"))]
pub fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
    GUARD
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_input() -> Value {
        json!({
            "version": "native.artifact-input.v1",
            "mode": "standalone",
            "collection": null,
            "records": [],
        })
    }

    fn grouped_count_envelope() -> Value {
        let buckets = vec![
            json!({ "key": "task", "count": 3 }),
            json!({ "key": "note", "count": 2 }),
        ];
        let buckets_sha256 = grouped_count_buckets_sha256(&buckets);
        json!({
            "version": "native.grouped-count-envelope.v1",
            "collection": { "id": "work", "kind": "folder" },
            "projection": {
                "kind": "grouped_count",
                "axis": { "kind": "record_field", "field": "kind" },
                "binding_event_seq": 41,
                "order": "count_desc_key_asc_null_first"
            },
            "total": 5,
            "buckets": buckets,
            "buckets_sha256": buckets_sha256
        })
    }

    fn relation_envelope(rows: Value) -> Value {
        let rows_sha256 = sha256_hex(&crate::mdx_v2::canonical_json_bytes(&rows));
        let count = rows.as_array().expect("relation rows").len();
        json!({
            "version": RELATION_ENVELOPE_VERSION,
            "source": {
                "kind": "collection", "id": "work", "collection_kind": "folder",
                "binding_revision": { "kind": "binding_event_seq", "value": 41 },
                "content_revision": { "kind": "content_event_seq", "id": "event-42", "value": 42 }
            },
            "relation": {
                "grain": "record", "key": ["id"], "row_schema": ARTIFACT_RECORD_SCHEMA_VERSION,
                "extent": { "complete": true, "returned": count, "total": count },
                "rows": rows, "rows_sha256": rows_sha256
            }
        })
    }

    fn governed_relation_envelope(truncated: bool, completeness: &str) -> Value {
        let columns = json!([
            { "name": "relationship_key", "type": "identifier", "nullable": false },
            { "name": "effective_state", "type": "text", "nullable": false }
        ]);
        let rows = json!([{ "relationship_key": "rel:one", "effective_state": "supported" }]);
        let count = rows.as_array().unwrap().len();
        json!({
            "version": RELATION_ENVELOPE_VERSION,
            "source": {
                "kind": "collection", "id": "relationships", "collection_kind": "query",
                "binding_revision": { "kind": "binding_event_seq", "value": 41 },
                "content_revision": {
                    "kind": "opaque_snapshot",
                    "token": format!("native.snapshot.v1.{}", "a".repeat(64))
                },
                "execution_receipt": {
                    "version": "native.governed-sql-port-receipt.v1",
                    "observed_at": "2026-09-01T12:00:00.000Z",
                    "row_count": count,
                    "truncated": truncated,
                    "completeness": completeness,
                    "replayable": false,
                    "observation_window_hours": 24,
                    "catalog_revision": 2,
                    "relations": [{
                        "name": "effective_relationships",
                        "identity": "native.query-sql.effective-relationships",
                        "semantic_version": 1
                    }],
                    "degraded_sources": []
                }
            },
            "relation": {
                "grain": "governed_sql",
                "key": ["relationship_key"],
                "schema_sha256": sha256_hex(&crate::mdx_v2::canonical_json_bytes(&columns)),
                "columns": columns,
                "extent": {
                    "complete": !truncated,
                    "returned": count,
                    "total": if truncated { Value::Null } else { json!(count) },
                    "truncated": truncated,
                    "source_completeness": completeness
                },
                "rows_sha256": sha256_hex(&crate::mdx_v2::canonical_json_bytes(&rows)),
                "rows": rows
            }
        })
    }

    fn artifact_record(id: &str) -> Value {
        json!({
            "id": id, "type": "WorkItem", "kind": "task", "name": "One",
            "summary": null, "lifecycle_interpretation": { "status": "absent" }, "maturity": null,
            "persistence": "enduring", "facets": { "status": "todo" }
        })
    }

    fn render_bar_chart(data_expression: &str) -> Result<Value, Failure> {
        let source = format!(
            r#"export const nativeArtifact = {{
  schema: "native.mdx.artifact.v2",
  inputs: {{ counts: {{
    envelope: "native.grouped-count-envelope.v1", required: true, expose_to_root: true,
    projection: {{ kind: "grouped_count", axis: {{ kind: "record_field", field: "kind" }} }}
  }} }},
  module_inputs: {{}},
  capability_requests: [{{ capability: "input.read", scope: {{ port: "counts" }} }}],
  interactions: []
}}

<BarChart label="Items by kind" data={{{data_expression}}} />
"#
        );
        let parsed = crate::mdx_v2::parse_artifact(&source)?;
        let envelope = grouped_count_envelope();
        let input = json!({
            "version": crate::mdx_v2::NAMED_INPUT_ABI,
            "mode": "named",
            "inputs": {},
            "records": []
        });
        let contexts = json!({ "$root": { "inputs": { "counts": envelope } } });
        let root = format!(
            "const native=globalThis.__nativeBridge.context(\"$root\");\n{}",
            parsed.compiled
        );
        crate::mdx_v2::render_verified(&root, HashMap::new(), &input, &contexts)
            .map(|(tree, _)| tree)
    }

    #[test]
    fn bar_chart_accepts_only_the_authenticated_envelope_and_emits_closed_data() {
        let _guard = test_guard();
        let tree = render_bar_chart("native.inputs.counts").expect("host envelope renders");
        assert_eq!(tree["type"], "BarChart");
        assert_eq!(tree["props"]["label"], "Items by kind");
        assert_eq!(tree["props"]["total"], 5);
        assert_eq!(
            tree["props"]["buckets"],
            grouped_count_envelope()["buckets"]
        );
        assert_eq!(tree["children"], json!([]));
        for forbidden in ["data", "version", "projection", "buckets_sha256"] {
            assert!(
                tree["props"].get(forbidden).is_none(),
                "the safe tree must not retain grouped envelope field {forbidden}"
            );
        }

        for forged in [
            "({...native.inputs.counts})",
            "({...native.inputs.counts, buckets: [...native.inputs.counts.buckets]})",
            "native.inputs.counts.buckets",
            "({version:'native.grouped-count-envelope.v1',collection:{id:'work',kind:'folder'},projection:{kind:'grouped_count',axis:{kind:'record_field',field:'kind'},binding_event_seq:41,order:'count_desc_key_asc_null_first'},total:5,buckets:[{key:'task',count:3},{key:'note',count:2}],buckets_sha256:native.inputs.counts.buckets_sha256})",
        ] {
            let failure = render_bar_chart(forged).expect_err("fabricated chart data fails");
            assert_eq!(failure.code, "mdx_capability_denied", "expression: {forged}");
        }

        let legacy = render(
            "<BarChart label=\"Items\" data={{version:'native.grouped-count-envelope.v1'}} />",
            &empty_input(),
        )
        .expect_err("the v1 component policy remains unchanged");
        assert_eq!(legacy.code, "mdx_unknown_component");
    }

    fn execute_scoped_v2(
        authored_source: &str,
        host_prefix: &str,
        input: &Value,
        contexts: &Value,
    ) -> Result<Value, Failure> {
        let compiled = compile_v2_source(authored_source)?;
        let root = format!("{host_prefix}\n{compiled}");
        let serialized = execute_v2_graph(
            &root,
            HashMap::new(),
            input,
            contexts,
            &mut ExecutionPhases::default(),
        )?;
        let mut tree: Value = serde_json::from_str(&serialized)
            .map_err(|_| output_failure("test safe tree did not decode"))?;
        validate_v2_tree_with_contexts(&mut tree, input, contexts)?;
        Ok(tree)
    }

    #[test]
    fn scoped_context_authority_is_available_to_child_output_but_not_root_props() {
        let _guard = test_guard();
        let counts = grouped_count_envelope();
        let record = json!({
            "id": "one", "type": "WorkItem", "kind": "task", "name": "One",
            "summary": null, "lifecycle": "active", "maturity": null,
            "persistence": "enduring", "facets": {}
        });
        let input = json!({
            "version": crate::mdx_v2::NAMED_INPUT_ABI,
            "mode": "named",
            "inputs": {},
            "records": []
        });
        let contexts = json!({
            "$root": { "inputs": {} },
            "$child": { "inputs": {
                "counts": counts,
                "rows": {
                    "version": "native.collection-envelope.v1",
                    "records": [record]
                }
            } }
        });

        let root_chart = execute_scoped_v2(
            r#"<BarChart label="Root" data={props.input.inputs.counts} />"#,
            "",
            &input,
            &contexts,
        )
        .expect_err("root props cannot borrow a child-only aggregate");
        assert_eq!(root_chart.code, "mdx_capability_denied");

        let root_record = execute_scoped_v2(
            r#"<RecordCard record={props.input.records[0]} fields={["kind"]} />"#,
            "",
            &input,
            &contexts,
        )
        .expect_err("root props cannot borrow a child-only record");
        assert_eq!(root_record.code, "mdx_capability_denied");

        let chart = execute_scoped_v2(
            "{Child()}",
            r#"const __childContext=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("BarChart",{label:"Child",data:__childContext.inputs.counts});"#,
            &input,
            &contexts,
        )
        .expect("host-scoped child aggregate renders");
        assert_eq!(chart["children"][0]["type"], "BarChart");
        assert_eq!(chart["children"][0]["props"]["total"], 5);

        let card = execute_scoped_v2(
            "{Child()}",
            r#"const __childContext=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("RecordCard",{record:__childContext.inputs.rows.records[0],fields:["kind"]});"#,
            &input,
            &contexts,
        )
        .expect("host-scoped child record renders");
        assert_eq!(card["children"][0]["type"], "RecordCard");
        assert_eq!(card["children"][0]["props"]["record"]["id"], "one");

        for host_prefix in [
            r#"const __childContext=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("BarChart",{label:"Clone",data:{...__childContext.inputs.counts}});"#,
            r#"const __childContext=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("BarChart",{label:"Clone",data:{...__childContext.inputs.counts,buckets:[...__childContext.inputs.counts.buckets]}});"#,
        ] {
            let cloned = execute_scoped_v2("{Child()}", host_prefix, &input, &contexts)
                .expect_err("a child cannot clone its authenticated aggregate");
            assert_eq!(cloned.code, "mdx_capability_denied");
        }
    }

    #[test]
    fn relation_rows_are_authenticated_and_malformed_envelopes_fail_before_authored_code() {
        let _guard = test_guard();
        let input = json!({
            "version": crate::mdx_v2::NAMED_INPUT_ABI,
            "mode": "named", "inputs": {}, "records": []
        });
        let envelope = relation_envelope(json!([artifact_record("one")]));
        let contexts = json!({ "$child": { "inputs": { "rows": envelope } } });
        let tree = execute_scoped_v2(
            "{Child()}",
            r#"const child=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("RecordTable",{records:child.inputs.rows.relation.rows,columns:["name","status"]});"#,
            &input,
            &contexts,
        )
        .expect("canonical relation rows render through record components");
        assert_eq!(tree["children"][0]["type"], "RecordTable");
        assert_eq!(tree["children"][0]["props"]["records"][0]["id"], "one");

        let mut invalid = Vec::new();
        let valid = contexts["$child"]["inputs"]["rows"].clone();
        let opaque = governed_relation_envelope(false, "best_effort");
        validate_relation_envelope(&opaque).expect("typed governed SQL relations are accepted");
        validate_relation_envelope(&governed_relation_envelope(true, "best_effort"))
            .expect("truncated best-effort relations are accepted");
        validate_relation_envelope(&governed_relation_envelope(false, "complete"))
            .expect("complete governed relations are accepted");
        validate_relation_envelope(&governed_relation_envelope(true, "truncated"))
            .expect("truncated governed relations are accepted");
        let mut leaked_boundary = governed_relation_envelope(false, "best_effort");
        leaked_boundary["source"]["execution_receipt"]["boundary"] =
            json!({ "content_event_seq": 42 });
        assert!(validate_relation_envelope(&leaked_boundary).is_err());
        let mut conflicting_receipt = governed_relation_envelope(false, "best_effort");
        conflicting_receipt["source"]["execution_receipt"]["row_count"] = json!(2);
        assert!(validate_relation_envelope(&conflicting_receipt).is_err());
        let mut record_with_receipt = relation_envelope(json!([artifact_record("one")]));
        record_with_receipt["source"]["execution_receipt"] =
            governed_relation_envelope(false, "best_effort")["source"]["execution_receipt"].clone();
        assert!(validate_relation_envelope(&record_with_receipt).is_err());
        let mut wrong_complete_tuple = governed_relation_envelope(false, "truncated");
        assert!(validate_relation_envelope(&wrong_complete_tuple).is_err());
        wrong_complete_tuple["relation"]["extent"]["source_completeness"] = json!("complete");
        wrong_complete_tuple["relation"]["extent"]["truncated"] = json!(true);
        wrong_complete_tuple["relation"]["extent"]["complete"] = json!(false);
        wrong_complete_tuple["relation"]["extent"]["total"] = Value::Null;
        assert!(validate_relation_envelope(&wrong_complete_tuple).is_err());
        let mut malformed_opaque = opaque;
        malformed_opaque["source"]["content_revision"]["token"] =
            json!(format!("native.snapshot.v1.{}", "A".repeat(64)));
        invalid.push(malformed_opaque);
        let mut wrong_digest = valid.clone();
        wrong_digest["relation"]["rows_sha256"] = json!("0".repeat(64));
        invalid.push(wrong_digest);
        let mut wrong_version = valid.clone();
        wrong_version["version"] = json!("native.relation-envelope.v0");
        invalid.push(wrong_version);
        let mut missing_version = valid.clone();
        missing_version.as_object_mut().unwrap().remove("version");
        invalid.push(missing_version);
        let mut unsafe_binding_revision = valid.clone();
        unsafe_binding_revision["source"]["binding_revision"]["value"] =
            json!(MAX_JSON_SAFE_INTEGER + 1);
        invalid.push(unsafe_binding_revision);
        let mut unsafe_content_revision = valid.clone();
        unsafe_content_revision["source"]["content_revision"]["value"] =
            json!(MAX_JSON_SAFE_INTEGER + 1);
        invalid.push(unsafe_content_revision);
        let mut wrong_key = valid.clone();
        wrong_key["relation"]["key"] = json!(["name"]);
        invalid.push(wrong_key);
        let mut wrong_extent = valid.clone();
        wrong_extent["relation"]["extent"]["total"] = json!(2);
        invalid.push(wrong_extent);
        let mut duplicate =
            relation_envelope(json!([artifact_record("one"), artifact_record("one")]));
        duplicate["relation"]["extent"]["returned"] = json!(2);
        invalid.push(duplicate);
        let mut extra_row_field = valid;
        extra_row_field["relation"]["rows"][0]["debug"] = json!(true);
        extra_row_field["relation"]["rows_sha256"] = json!(sha256_hex(
            &crate::mdx_v2::canonical_json_bytes(&extra_row_field["relation"]["rows"])
        ));
        invalid.push(extra_row_field);
        invalid.push(relation_envelope(json!((0..=MAX_INPUT_RECORDS)
            .map(|index| artifact_record(&format!("row-{index}")))
            .collect::<Vec<_>>())));
        let mut oversized = artifact_record("oversized");
        oversized["summary"] = json!("x".repeat(MAX_INPUT_BYTES + 1));
        invalid.push(relation_envelope(json!([oversized])));

        for envelope in invalid {
            let contexts = json!({ "$child": { "inputs": { "rows": envelope } } });
            let failure = execute_scoped_v2(
                "<Metric label=\"Authored code must not run\" value={1} />",
                "",
                &input,
                &contexts,
            )
            .expect_err("invalid relation envelope fails at the input boundary");
            assert!(matches!(
                failure.code,
                "mdx_output_invalid" | "mdx_resource_limit_exceeded"
            ));
            assert_eq!(failure.details["phase"], "input");
        }

        let cloned = execute_scoped_v2(
            "{Child()}",
            r#"const child=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("RecordCard",{record:{...child.inputs.rows.relation.rows[0]},fields:["kind"]});"#,
            &input,
            &contexts,
        )
        .expect_err("authored clones are not canonical relation rows");
        assert_eq!(cloned.code, "mdx_capability_denied");

        for (source, component) in [
            (
                r#"{Child()}"#,
                r#"const child=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("FacetControl",{entry:"set_status",record:child.inputs.rows.relation.rows[0]});"#,
            ),
            (
                r#"{Child()}"#,
                r#"const child=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("RecordCard",{record:child.inputs.rows.relation.rows[0],fields:["kind"],draggable:true});"#,
            ),
            (
                r#"{Child()}"#,
                r#"const child=globalThis.__nativeBridge.context("$child");
const Child=()=>globalThis.__nativeBridge.jsx("DropTarget",{entry:"place"},globalThis.__nativeBridge.jsx("PlacementPreview",{recordId:child.inputs.rows.relation.rows[0].id},globalThis.__nativeBridge.jsx("span",{},"preview")));"#,
            ),
        ] {
            let failure = execute_scoped_v2(source, component, &input, &contexts)
                .expect_err("relation-only records cannot render write affordances");
            assert_eq!(failure.code, "mdx_capability_denied");
        }
    }

    #[test]
    fn bar_chart_rust_boundary_revalidates_digest_shape_bounds_and_order() {
        fn validate(envelope: Value) -> Result<Value, Failure> {
            let input = json!({ "inputs": {}, "records": [] });
            let contexts = json!({ "$child": { "inputs": { "counts": envelope.clone() } } });
            let mut tree = json!({
                "type": "BarChart",
                "props": { "label": "Items by kind", "data": envelope },
                "children": []
            });
            validate_v2_tree_with_contexts(&mut tree, &input, &contexts).map(|_| tree)
        }

        let valid = validate(grouped_count_envelope()).expect("valid envelope is canonicalized");
        assert_eq!(valid["props"]["total"], 5);
        assert!(valid["props"].get("data").is_none());

        let mut facet = grouped_count_envelope();
        facet["projection"]["axis"] = json!({ "kind": "facet", "key": "status" });
        validate(facet).expect("a canonical facet envelope is accepted");

        let envelope = grouped_count_envelope();
        let input = json!({ "inputs": {}, "records": [] });
        let contexts = json!({ "$child": { "inputs": { "counts": envelope.clone() } } });
        let mut styled = json!({
            "type": "BarChart",
            "props": { "label": "Items by kind", "data": envelope, "class": "chart" },
            "children": []
        });
        let styled_failure = validate_v2_tree_with_contexts(&mut styled, &input, &contexts)
            .expect_err("the closed chart surface has no author styling authority");
        assert_eq!(styled_failure.details["rule"], "bar_chart_closed_surface");

        let mut invalid = Vec::new();

        let mut wrong_digest = grouped_count_envelope();
        wrong_digest["buckets_sha256"] = json!("0".repeat(64));
        invalid.push(wrong_digest);

        let mut wrong_axis = grouped_count_envelope();
        wrong_axis["projection"]["axis"]["field"] = json!("type");
        invalid.push(wrong_axis);

        for axis in [
            json!({ "kind": "facet", "key": "" }),
            json!({ "kind": "facet", "key": "   " }),
            json!({ "kind": "facet", "key": "bad\u{0000}key" }),
            json!({ "kind": "facet", "key": "x".repeat(crate::mdx_v2::MAX_FACET_KEY_BYTES + 1) }),
            json!({ "kind": "facet" }),
            json!({ "kind": "facet", "key": "status", "field": "kind" }),
            json!({ "kind": "path", "key": "status" }),
        ] {
            let mut invalid_axis = grouped_count_envelope();
            invalid_axis["projection"]["axis"] = axis;
            invalid.push(invalid_axis);
        }

        let mut wrong_total = grouped_count_envelope();
        wrong_total["total"] = json!(4);
        invalid.push(wrong_total);

        let mut unordered = grouped_count_envelope();
        unordered["buckets"] = json!([
            { "key": "note", "count": 2 },
            { "key": "task", "count": 3 }
        ]);
        unordered["buckets_sha256"] = json!(grouped_count_buckets_sha256(
            unordered["buckets"].as_array().unwrap()
        ));
        invalid.push(unordered);

        let mut zero = grouped_count_envelope();
        zero["buckets"] = json!([{ "key": "task", "count": 5 }, { "key": "empty", "count": 0 }]);
        zero["buckets_sha256"] = json!(grouped_count_buckets_sha256(
            zero["buckets"].as_array().unwrap()
        ));
        invalid.push(zero);

        let mut extra = grouped_count_envelope();
        extra["debug"] = json!(true);
        invalid.push(extra);

        for envelope in invalid {
            assert_eq!(
                validate(envelope)
                    .expect_err("invalid host envelope fails")
                    .code,
                "mdx_output_invalid"
            );
        }

        let empty_buckets: Vec<Value> = Vec::new();
        let empty = json!({
            "version": "native.grouped-count-envelope.v1",
            "collection": { "id": "work", "kind": "folder" },
            "projection": {
                "kind": "grouped_count",
                "axis": { "kind": "record_field", "field": "kind" },
                "binding_event_seq": 42,
                "order": "count_desc_key_asc_null_first"
            },
            "total": 0,
            "buckets": empty_buckets,
            "buckets_sha256": grouped_count_buckets_sha256(&[])
        });
        assert!(
            validate(empty).is_ok(),
            "an empty collection has no buckets"
        );
    }

    #[test]
    fn genuine_mdx_compiles_executes_and_reuses_verified_cache() {
        let _guard = test_guard();
        let source = "# Runtime pulse\n\n<Stack gap={2}><Metric label=\"Count\" value={props.input.records.length} /></Stack>";
        let first = render(source, &empty_input()).expect("first render");
        assert_eq!(first.cache_state, "miss");
        assert_eq!(first.tree["type"], "Fragment");
        assert_eq!(first.tree["children"][0]["type"], "h1");
        assert_eq!(first.tree["children"][2]["type"], "Stack");
        assert_eq!(first.tree["children"][2]["props"]["gap"], 2);
        let second = render(source, &empty_input()).expect("second render");
        assert_eq!(second.cache_state, "hit");
        assert_eq!(first.tree, second.tree);

        let list = render("- one\n- two", &empty_input()).expect("CommonMark list renders");
        assert_eq!(list.tree["type"], "ul");
        assert_eq!(
            list.tree["children"]
                .as_array()
                .expect("list children")
                .iter()
                .filter(|child| child["type"] == "li")
                .count(),
            2
        );

        let sentinel_input = json!({
            "version": "native.artifact-input.v1",
            "mode": "bound",
            "collection": null,
            "records": [{ "id": "sentinel", "name": "__NATIVE_ALLOWED__ __NATIVE_COMPONENTS__" }],
        });
        let sentinel = render(
            "<Metric label=\"sentinel\" value={props.input.records[0].name} />",
            &sentinel_input,
        )
        .expect("template sentinels remain input data");
        assert_eq!(
            sentinel.tree["props"]["value"],
            "__NATIVE_ALLOWED__ __NATIVE_COMPONENTS__"
        );

        corrupt_cache_for(source);
        assert_eq!(
            render(source, &empty_input()).unwrap().cache_state,
            "rebuilt_corrupt"
        );

        let partitioned_source = "# principal partition";
        assert_eq!(
            render_partitioned(
                "test-artifact",
                partitioned_source,
                &empty_input(),
                "principal-a"
            )
            .unwrap()
            .cache_state,
            "miss"
        );
        assert_eq!(
            render_partitioned(
                "test-artifact",
                partitioned_source,
                &empty_input(),
                "principal-b"
            )
            .unwrap()
            .cache_state,
            "miss"
        );
        assert_eq!(
            render_partitioned(
                "test-artifact",
                partitioned_source,
                &empty_input(),
                "principal-a"
            )
            .unwrap()
            .cache_state,
            "hit"
        );
    }

    #[test]
    fn authored_modules_unknown_components_and_fabricated_records_fail_closed() {
        let _guard = test_guard();
        let module =
            validate_source("test-artifact", "import x from 'somewhere'\n\n# no").unwrap_err();
        assert_eq!(module.code, "mdx_policy_violation");

        let unknown = render("<Button>no</Button>", &empty_input()).unwrap_err();
        assert_eq!(unknown.code, "mdx_unknown_component");

        let fabricated = render(
            "<RecordCard record={{id: 'invented', name: 'No'}} />",
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(fabricated.code, "mdx_capability_denied");
    }

    #[test]
    fn ambient_authority_async_and_programmatic_urls_are_denied() {
        let _guard = test_guard();
        let random = render(
            "<Metric label=\"x\" value={Math.random()} />",
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(random.code, "mdx_capability_denied");

        let async_value = render("{Promise.resolve('later')}", &empty_input()).unwrap_err();
        assert!(matches!(
            async_value.code,
            "mdx_output_invalid" | "mdx_runtime_failed"
        ));

        let url = render("[bad](javascript:alert(1))", &empty_input()).unwrap_err();
        assert_eq!(url.code, "mdx_output_invalid");
    }

    #[test]
    fn dynamic_code_constructor_chains_and_ambient_authority_fail_closed() {
        let _guard = test_guard();
        let normal = render("<Metric label=\"x\" value={(() => 7)()} />", &empty_input())
            .expect("ordinary authored functions remain supported");
        assert_eq!(normal.tree["props"]["value"], 7);

        for expression in [
            "Function('return 7')()",
            "(0, eval)('7')",
            "(() => {}).constructor('return 7')()",
            "({}).constructor.constructor('return 7')()",
            "Reflect.get(() => {}, 'constructor')('return 7')()",
            "(async () => {}).constructor('return 7')()",
            "(function* () {}).constructor('return 7')()",
            "(async function* () {}).constructor('return 7')()",
        ] {
            let source = format!("<Metric label=\"x\" value={{{expression}}} />");
            let failure = render(&source, &empty_input()).unwrap_err();
            assert_eq!(failure.code, "mdx_capability_denied", "{expression}");
        }

        for expression in [
            "fetch('https://example.com')",
            "new XMLHttpRequest()",
            "new WebSocket('wss://example.com')",
            "new EventSource('https://example.com')",
            "process.cwd()",
            "localStorage.getItem('x')",
            "sessionStorage.getItem('x')",
            "Date.now()",
            "performance.now()",
            "setTimeout(() => {}, 1)",
            "crypto.getRandomValues(new Uint8Array(1))",
            "Intl.DateTimeFormat()",
            "window.location",
            "document.body",
        ] {
            let source = format!("<Metric label=\"x\" value={{{expression}}} />");
            let failure = render(&source, &empty_input()).unwrap_err();
            assert_eq!(failure.code, "mdx_runtime_failed", "{expression}");
        }

        let mutation = render(
            "<Metric label=\"x\" value={props.input.mode = 'changed'} />",
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(mutation.code, "mdx_runtime_failed");

        let stateful =
            "<Metric label=\"x\" value={globalThis.__attempt = (globalThis.__attempt || 0) + 1} />";
        assert_eq!(
            render(stateful, &empty_input()).unwrap().tree["props"]["value"],
            1
        );
        assert_eq!(
            render(stateful, &empty_input()).unwrap().tree["props"]["value"],
            1
        );
    }

    #[test]
    fn urls_and_images_share_one_canonical_fail_closed_contract() {
        let _guard = test_guard();
        let canonical = render(
            r#"<a href={"HTTPS://EXAMPLE.com:443/a/../path?q=a b"}>leave</a>"#,
            &empty_input(),
        )
        .unwrap();
        assert_eq!(
            canonical.tree["props"]["href"],
            "https://example.com/path?q=a%20b"
        );
        let short = render(
            r#"<a href={"https:example.com/a/../b"}>leave</a>"#,
            &empty_input(),
        )
        .unwrap();
        assert_eq!(short.tree["props"]["href"], "https://example.com/b");
        assert_eq!(
            render("<a href=\"#inside\">stay</a>", &empty_input())
                .unwrap()
                .tree["props"]["href"],
            "#inside"
        );

        for href in [
            "https://user:secret@example.com/x",
            "//example.com/x",
            "javascript:alert(1)",
            "data:text/plain,no",
            "file:///tmp/no",
            "blob:https://example.com/id",
            "/relative",
        ] {
            let source = format!("<a href={{\"{href}\"}}>no</a>");
            let failure = render(&source, &empty_input()).unwrap_err();
            assert_eq!(failure.code, "mdx_output_invalid", "{href:?}");
        }
        assert_eq!(
            validate_href("https://exa\nmple.com").unwrap_err().code,
            "mdx_output_invalid"
        );

        for (media, bytes) in [
            ("png", b"\x89PNG\r\n\x1a\n".as_slice()),
            ("jpeg", b"\xff\xd8\xff".as_slice()),
            ("gif", b"GIF89a".as_slice()),
            ("webp", b"RIFFxxxxWEBP".as_slice()),
        ] {
            let src = format!(
                "data:image/{media};base64,{}",
                base64::engine::general_purpose::STANDARD.encode(bytes)
            );
            validate_image(&src).expect(media);
        }
        for src in [
            "https://example.com/x.png",
            "data:image/svg+xml;base64,PHN2Zy8+",
            "data:image/png;base64,not-base64",
            "data:image/png;base64,R0lGODlh",
        ] {
            assert_eq!(validate_image(src).unwrap_err().code, "mdx_output_invalid");
        }
        let blank_alt = render(
            "<img src=\"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==\" alt=\" \" />",
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(blank_alt.code, "mdx_output_invalid");
    }

    #[test]
    fn complete_component_policy_accepts_only_declared_props() {
        let _guard = test_guard();
        let input = json!({
            "version": "native.artifact-input.v1",
            "mode": "bound",
            "collection": { "id": "collection", "kind": "folder" },
            "records": [{
                "id": "one", "type": "WorkItem", "kind": "task", "name": "One",
                "summary": null, "lifecycle": "active", "maturity": null,
                "persistence": "enduring", "facets": { "status": "doing" }
            }]
        });
        let source = r##"
<>
  <h1>h1</h1><h2>h2</h2><h3>h3</h3><h4>h4</h4><h5>h5</h5><h6>h6</h6>
  <p>p</p><span>span</span><div>div</div><section>section</section><article>article</article>
  <ul><li>ul</li></ul><ol><li>ol</li></ol><blockquote>quote</blockquote><pre><code>code</code></pre>
  <em>em</em><strong>strong</strong><del>del</del><hr /><br />
  <table><thead><tr><th>h</th></tr></thead><tbody><tr><td>d</td></tr></tbody></table>
  <a href="#here">link</a>
  <img src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==" alt="pixel" />
  <Stack gap={1}>stack</Stack><Grid columns={2} gap={2}>grid</Grid>
  <Callout tone="warning" title="callout">callout</Callout><Badge tone="success">badge</Badge>
  <Metric label="metric" value={1} detail="detail" />
  <RecordList records={props.input.records} empty="empty" />
  <RecordTable records={props.input.records} columns={['name', 'status']} />
  <RecordCard record={props.input.records[0]} fields={['name', 'status']} />
  <Field record={props.input.records[0]} field="status" />
  <EmptyState title="empty">none</EmptyState>
</>
"##;
        let rendered = render(source, &input).expect("complete allowlist renders");
        let encoded = serde_json::to_string(&rendered.tree).unwrap();
        for name in INTRINSICS.iter().chain(NATIVE_COMPONENTS.iter()) {
            assert!(
                encoded.contains(&format!("\"type\":\"{name}\"")),
                "missing {name}"
            );
        }

        let unknown_prop = render("<Stack gap={2} className=\"escape\" />", &input).unwrap_err();
        assert_eq!(unknown_prop.code, "mdx_capability_denied");
        // `class` is a native.mdx.v2 affordance, because author CSS is. There
        // is no v1 stylesheet for it to name, so v1 keeps refusing it, and the
        // v1 tree contract is exactly what it was.
        let v1_class = render("<Stack gap={2} class=\"card\" />", &input).unwrap_err();
        assert_eq!(v1_class.code, "mdx_capability_denied");
        assert_eq!(v1_class.details["rule"], "ambient_authority");
        let unknown_field = render(
            "<Field record={props.input.records[0]} field=\"secret\" />",
            &input,
        )
        .unwrap_err();
        assert_eq!(unknown_field.code, "mdx_output_invalid");
    }

    #[test]
    fn component_props_children_and_raw_dom_rejections_are_explicit() {
        let _guard = test_guard();
        let input = json!({
            "version": "native.artifact-input.v1", "mode": "bound",
            "collection": { "id": "collection", "kind": "folder" },
            "records": [{
                "id": "one", "type": "WorkItem", "kind": "task", "name": "One",
                "summary": null, "lifecycle": "active", "maturity": null,
                "persistence": "enduring", "facets": { "status": "doing" }
            }]
        });

        for source in [
            "<Badge tone=\"info\"><span>nested</span></Badge>",
            "<EmptyState><strong>nested</strong></EmptyState>",
            "<Callout tone=\"info\" title={1}>x</Callout>",
            "<EmptyState title={1}>x</EmptyState>",
            "<img src=\"data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==\" alt=\"pixel\" children=\"ignored\" />",
            "<br children=\"ignored\" />",
            "<hr children=\"ignored\" />",
            "<p id=\"unknown\">x</p>",
            "<Stack gap={2} unknown=\"x\" />",
            "<Metric label=\"x\" value={() => 1} />",
        ] {
            let failure = render(source, &input).unwrap_err();
            assert_eq!(failure.code, "mdx_output_invalid", "{source}");
        }

        for source in [
            "<p onClick={() => 1}>x</p>",
            "<p ref={{}}>x</p>",
            "<p style={{color:'red'}}>x</p>",
            "<p className=\"x\">x</p>",
            "<p dangerouslySetInnerHTML={{__html:'x'}} />",
            "<p key=\"x\">x</p>",
        ] {
            let failure = render(source, &input).unwrap_err();
            assert_eq!(failure.code, "mdx_capability_denied", "{source}");
        }

        for name in [
            "form", "input", "button", "x-custom", "svg", "math", "audio", "video", "iframe",
            "script",
        ] {
            let source = format!("<{name} />");
            assert_eq!(
                render(&source, &input).unwrap_err().code,
                "mdx_unknown_component",
                "{name}"
            );
        }

        for source in [
            "<Stack />",
            "<Stack gap={5} />",
            "<Grid columns={0} gap={1} />",
            "<Callout tone=\"loud\" />",
            "<Badge tone=\"loud\">x</Badge>",
            "<Metric value={1} />",
            "<RecordTable records={props.input.records} columns={[]} />",
            "<RecordCard record={props.input.records[0]} fields={[1]} />",
            "<Field record={props.input.records[0]} field=\"missing\" />",
        ] {
            assert_eq!(
                render(source, &input).unwrap_err().code,
                "mdx_output_invalid",
                "{source}"
            );
        }
        assert_eq!(
            render("<RecordList records={{}} />", &input)
                .unwrap_err()
                .code,
            "mdx_capability_denied"
        );
        for source in [
            "<FacetControl entry=\"set_status\" record={props.input.records[0]} />",
            "<DropTarget entry=\"set_status\" />",
            "<PlacementPreview recordId={props.input.records[0].id}><span>dot</span></PlacementPreview>",
        ] {
            assert_eq!(
                render(source, &input).unwrap_err().code,
                "mdx_unknown_component",
                "legacy native.mdx.v1 must not gain writable leaves: {source}"
            );
        }
        assert_eq!(
            render(
                "<RecordCard record={props.input.records[0]} draggable={true} />",
                &input
            )
            .unwrap_err()
            .code,
            "mdx_output_invalid",
            "legacy RecordCard keeps its original prop contract"
        );
    }

    #[test]
    fn card_fields_are_validated_against_every_input_record() {
        let _guard = test_guard();
        // Two records, one carrying `area` and one not — the ordinary shape of
        // a heterogeneous collection, and the shape that used to refuse.
        let input = json!({
            "version": "native.artifact-input.v1", "mode": "bound",
            "collection": { "id": "collection", "kind": "folder" },
            "records": [
                {
                    "id": "one", "type": "WorkItem", "kind": "task", "name": "One",
                    "summary": null, "lifecycle": "active", "maturity": null,
                    "persistence": "enduring", "facets": { "area": "artifacts" }
                },
                {
                    "id": "two", "type": "WorkItem", "kind": "task", "name": "Two",
                    "summary": null, "lifecycle": "active", "maturity": null,
                    "persistence": "enduring", "facets": {}
                }
            ]
        });

        // The card is bound to the record *without* the facet. The workbench
        // renders it as an empty field; the validator must not refuse it.
        render(
            "<RecordCard record={props.input.records[1]} fields={['name', 'area']} />",
            &input,
        )
        .expect("a card may name a facet only some input records carry");

        // A card and the equivalent table column now agree, which is the point.
        render(
            "<RecordTable records={props.input.records} columns={['name', 'area']} />",
            &input,
        )
        .expect("a table column carried by one record has always rendered");

        // The typo case survives: absent from every input record, still refused.
        let typo = render(
            "<RecordCard record={props.input.records[0]} fields={['aera']} />",
            &input,
        )
        .unwrap_err();
        assert_eq!(typo.code, "mdx_output_invalid");
        assert!(
            typo.message.contains("aera"),
            "the failure must name the field: {}",
            typo.message
        );
    }

    #[test]
    fn descriptor_and_normative_limits_are_exact() {
        let _guard = test_guard();
        assert_eq!(
            descriptor(),
            json!({
                "id": "native.mdx.v1",
                "contract_version": 1,
                "adapter_revision": 1,
                "body_media_type": "text/mdx; charset=utf-8",
                "source_encoding": "utf-8",
                "compiler": {
                    "id": "mdxjs-rs", "crate": "mdxjs", "version": "1.0.4",
                    "options_profile": "native.mdx.compile.v1", "development": false,
                    "jsx_runtime": "automatic", "jsx_import_source": "native.mdx.v1",
                    "provider_import_source": "native.mdx.v1/provider", "plugins": []
                },
                "executor": {
                    "id": "rquickjs.quickjs-ng", "crate": "rquickjs", "version": "0.11.0",
                    "sys_crate": "rquickjs-sys@0.11.0", "profile": "native.mdx.quickjs.v1",
                    "module_loader": "compiler-modules-only-before-content"
                },
                "component_policy": { "id": "native.mdx.components", "version": 1 },
                "input_envelope_version": "native.artifact-input.v1",
                "execution_profile": "sandboxed",
                "requested_capabilities": [],
                "granted_capabilities": ["input.read", "navigation.record.user_gesture", "navigation.external.user_gesture"],
                "output_surface": "workbench.safe-tree.v1",
                "diagnostic_format": "native.artifact-diagnostic.v1",
                "limits": {
                    "source_utf8_bytes": 524288, "input_records": 10000,
                    "input_json_bytes": 8388608, "quickjs_heap_bytes": 67108864,
                    "quickjs_stack_bytes": 524288, "execution_interrupt_ticks": 250000,
                    "output_nodes": 10000,
                    "output_depth": 64, "output_json_bytes": 2097152,
                    "data_image_decoded_bytes": 262144
                }
            })
        );
        assert_eq!(
            cache_key(&"00".repeat(32)),
            "e6da80c4eae7553d7bf6d312cb198a3c0019ad5fe1c3579e0b6ac06b07481cfb"
        );
        assert_ne!(cache_key(&"00".repeat(32)), cache_key(&"01".repeat(32)));
        let records = (0..=MAX_INPUT_RECORDS)
            .map(|index| json!({ "id": index.to_string() }))
            .collect::<Vec<_>>();
        let oversized = render(
            "# bounded",
            &json!({
                "version": "native.artifact-input.v1", "mode": "bound",
                "collection": { "id": "collection", "kind": "folder" },
                "records": records
            }),
        )
        .unwrap_err();
        assert_eq!(oversized.details["limit"], "input_records");
    }

    #[test]
    fn source_input_tree_output_and_image_quotas_use_stable_limits() {
        let _guard = test_guard();
        let source = "x".repeat(MAX_SOURCE_BYTES + 1);
        let failure = validate_source("source-quota", &source).unwrap_err();
        assert_eq!(failure.code, "mdx_source_too_large");
        assert_eq!(failure.details["limit"], "source_utf8_bytes");

        let input = json!({
            "version": "native.artifact-input.v1", "mode": "bound", "collection": null,
            "records": [{ "id": "wide", "padding": "x".repeat(MAX_INPUT_BYTES) }],
        });
        let failure = render("# input bytes", &input).unwrap_err();
        assert_eq!(failure.code, "mdx_resource_limit_exceeded", "{failure:?}");
        assert_eq!(failure.details["limit"], "input_json_bytes");

        let mut depth_source = "deep".to_owned();
        for _ in 0..=MAX_TREE_DEPTH {
            depth_source = format!("<div>{depth_source}</div>");
        }
        let failure = render(&depth_source, &empty_input()).unwrap_err();
        assert_eq!(failure.code, "mdx_resource_limit_exceeded", "{failure:?}");
        assert_eq!(failure.details["limit"], "output_depth");

        let nodes_source = format!(
            "<div>{{Array.from({{length:{}}}, (_, i) => <span>{{i}}</span>)}}</div>",
            MAX_TREE_NODES
        );
        let failure = render(&nodes_source, &empty_input()).unwrap_err();
        assert_eq!(failure.code, "mdx_resource_limit_exceeded");
        assert_eq!(failure.details["limit"], "output_nodes");

        let bytes_source = format!("<p>{{'x'.repeat({})}}</p>", MAX_OUTPUT_BYTES + 1);
        let failure = render(&bytes_source, &empty_input()).unwrap_err();
        assert_eq!(failure.code, "mdx_resource_limit_exceeded");
        assert_eq!(failure.details["limit"], "output_json_bytes");

        let mut oversized_image = b"\x89PNG\r\n\x1a\n".to_vec();
        oversized_image.resize(MAX_IMAGE_BYTES + 1, 0);
        let src = format!(
            "data:image/png;base64,{}",
            base64::engine::general_purpose::STANDARD.encode(oversized_image)
        );
        let failure = render(
            &format!("<img src={{\"{src}\"}} alt=\"large\" />"),
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(failure.code, "mdx_resource_limit_exceeded");
        assert_eq!(failure.details["limit"], "data_image_decoded_bytes");
    }

    #[test]
    fn cpu_heap_and_stack_exhaustion_have_stable_quota_diagnostics() {
        let _guard = test_guard();
        let cpu = render("{(() => { while (true) {} })()}", &empty_input()).unwrap_err();
        assert_eq!(cpu.code, "mdx_resource_limit_exceeded");
        assert_eq!(cpu.details["limit"], "interrupt_ticks");

        let heap = render(
            "{(() => new ArrayBuffer(70 * 1024 * 1024))()}",
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(heap.code, "mdx_resource_limit_exceeded");
        assert_eq!(heap.details["limit"], "quickjs_heap_bytes");

        let stack = render(
            "{(() => { function dive() { return dive(); } return dive(); })()}",
            &empty_input(),
        )
        .unwrap_err();
        assert_eq!(stack.code, "mdx_resource_limit_exceeded", "{stack:?}");
        assert_eq!(stack.details["limit"], "quickjs_stack_bytes");
    }

    #[test]
    fn diagnostics_are_source_bounded_and_never_expose_generated_stacks() {
        let _guard = test_guard();
        let source = "# heading\n\n<Stack gap={\n";
        let compile = validate_source("compiler-location", source).unwrap_err();
        assert_eq!(compile.code, "mdx_compile_failed");
        assert_eq!(compile.details["artifact_id"], "compiler-location");
        assert_eq!(
            compile.details["body_sha256"],
            sha256_hex(source.as_bytes())
        );
        assert!(compile.details["line"].as_u64().is_some(), "{compile:?}");
        assert!(compile.details["column"].as_u64().is_some());
        assert!(compile.details["source_range"]["start"]["line"]
            .as_u64()
            .is_some_and(|line| line >= 1));

        let runtime_source =
            "# before\n\n{(() => { throw new Error('secret-runtime-message'); })()}";
        let runtime = render(runtime_source, &empty_input()).unwrap_err();
        assert_eq!(runtime.code, "mdx_runtime_failed");
        let encoded = serde_json::to_string(&runtime.details).unwrap();
        assert!(runtime.details["source_range"].is_object());
        assert!(!encoded.contains("secret-runtime-message"));
        assert!(!encoded.contains("native.mdx.v1/root"));
        assert!(!encoded.to_ascii_lowercase().contains("stack"));

        let dynamic = validate_source(
            "dynamic-import",
            "# no\n\n{import('https://example.com/module.js')}",
        )
        .unwrap_err();
        assert_eq!(dynamic.code, "mdx_policy_violation");
        assert_eq!(dynamic.details["rule"], "authored_module_syntax");
        assert!(dynamic.details["source_range"].is_object());
    }

    #[test]
    fn telemetry_is_bounded_aggregate_and_content_free() {
        let _guard = test_guard();
        *telemetry().lock().expect("telemetry lock") = TelemetryState::default();
        let secret_source = "# telemetry-secret-source";
        render_partitioned(
            "telemetry-artifact",
            secret_source,
            &empty_input(),
            "telemetry-principal",
        )
        .unwrap();
        validate_source("telemetry-invalid", "import secret from 'private-record'").unwrap_err();
        let snapshot = telemetry_snapshot();
        assert_eq!(snapshot["attempts"], 2);
        assert_eq!(snapshot["failures"], 1);
        assert_eq!(snapshot["cache"]["miss"], 1);
        assert_eq!(snapshot["events"].as_array().unwrap().len(), 2);
        assert!(snapshot["events"][0]["input_records"].is_number());
        assert!(snapshot["events"][0]["input_json_bytes"].is_number());
        assert!(snapshot["events"][0]["output_nodes"].is_number());
        assert!(snapshot["events"][0]["output_json_bytes"].is_number());
        assert!(snapshot["events"][0]["compile_micros"].is_number());
        assert!(snapshot["events"][0]["execute_micros"].is_number());
        assert!(snapshot["events"][1]["validate_micros"].is_number());
        assert_eq!(snapshot["events"][1]["diagnostic_phase"], "policy");
        let encoded = snapshot.to_string();
        assert!(!encoded.contains("telemetry-secret-source"));
        assert!(!encoded.contains("private-record"));
        assert!(!encoded.contains("telemetry-principal"));

        let template = TelemetryEvent::new("validate", "bounded", "# body");
        for _ in 0..MAX_TELEMETRY_EVENTS + 5 {
            observe(template.clone());
        }
        assert_eq!(
            telemetry_snapshot()["events"].as_array().unwrap().len(),
            MAX_TELEMETRY_EVENTS
        );
    }

    /// The seam a runtime outside this module reports through, end to end.
    ///
    /// v1's telemetry test above covers the v1 constructors. This one covers
    /// what `native.mdx.v2` actually does, and pins the three things that were
    /// wrong or missing before it could: that an event can claim a runtime and
    /// an adapter revision other than v1's, that phases beyond compile/execute/
    /// validate survive into the snapshot, and that the counters answer per
    /// runtime instead of summing two runtimes into one number.
    #[test]
    fn a_reported_render_carries_its_own_runtime_phases_and_no_content() {
        let _guard = test_guard();
        *telemetry().lock().expect("telemetry lock") = TelemetryState::default();

        let mut render = RenderTelemetry::begin("render", "native.mdx.v2", 4, "v2-artifact");
        render.identity("0123456789abtelemetry-secret-cache-key");
        render.phase("snapshot_replay");
        render.phase("resolve_inputs");
        render.cache_state("hit");
        render.absorb(ExecutionPhases {
            execute_micros: 10,
            decode_micros: 2,
            validate_micros: 3,
            input_records: 144,
            input_json_bytes: 4096,
            output_nodes: 900,
            output_json_bytes: 2048,
        });
        render.phase("plan_assembly");
        render.observe();

        let snapshot = telemetry_snapshot();
        let event = &snapshot["events"][0];
        // Not v1's, which is the whole point of parameterizing these.
        assert_eq!(event["runtime"], "native.mdx.v2");
        assert_ne!(event["runtime"], RUNTIME_ID);
        assert_eq!(event["adapter_revision"], 4);
        assert_eq!(event["cache_state"], "hit");

        // Phases with no typed field of their own still reach the snapshot.
        assert!(event["phases"]["snapshot_replay"].is_number());
        assert!(event["phases"]["resolve_inputs"].is_number());
        assert!(event["phases"]["plan_assembly"].is_number());
        assert!(event["phases"]["blocking_dispatch"].is_number());

        // The three v1 also reports are in both places, and agree.
        assert_eq!(event["execute_micros"], 10);
        assert_eq!(event["validate_micros"], 3);
        assert_eq!(event["phases"]["execute"], 10);
        assert_eq!(event["phases"]["validate"], 3);
        assert_eq!(event["phases"]["output_decode"], 2);
        assert_eq!(event["input_records"], 144);
        assert_eq!(event["input_json_bytes"], 4096);
        assert_eq!(event["output_nodes"], 900);
        assert_eq!(event["output_json_bytes"], 2048);

        // Per runtime, so a board's execute is not summed with a prospective
        // write's execute.
        let totals = &snapshot["runtimes"]["native.mdx.v2"];
        assert_eq!(totals["attempts"], 1);
        assert_eq!(totals["failures"], 0);
        assert_eq!(totals["execute_micros"], 10);
        assert_eq!(totals["validate_micros"], 3);
        assert!(totals["phase_micros"]["snapshot_replay"].is_number());
        assert!(
            snapshot["runtimes"].get(RUNTIME_ID).is_none(),
            "a runtime that did not render must not appear to have rendered"
        );

        // An identity is bounded to 12 characters whether or not it is a
        // digest, so a caller cannot widen this into a content channel.
        assert_eq!(event["body_digest_prefix"], "0123456789ab");
        assert!(!snapshot.to_string().contains("secret-cache-key"));
    }

    /// A failed render is still a render. v1 has always recorded its failures;
    /// v2's arrive as host diagnostics, where the code is a JSON string rather
    /// than a `'static` one.
    #[test]
    fn a_reported_render_records_a_host_diagnostic_outcome() {
        let _guard = test_guard();
        *telemetry().lock().expect("telemetry lock") = TelemetryState::default();

        let mut render = RenderTelemetry::begin("render", "native.mdx.v2", 4, "v2-artifact");
        render.phase("snapshot_replay");
        render.failed_with("named_input_incompatible", Some("preflight"));
        render.observe();

        let snapshot = telemetry_snapshot();
        assert_eq!(snapshot["failures"], 1);
        assert_eq!(
            snapshot["events"][0]["diagnostic_code"],
            "named_input_incompatible"
        );
        assert_eq!(snapshot["events"][0]["diagnostic_phase"], "preflight");
        assert_eq!(snapshot["runtimes"]["native.mdx.v2"]["failures"], 1);
    }

    #[test]
    fn nested_forgery_post_create_mutation_and_primordial_tampering_fail_closed() {
        let _guard = test_guard();
        let input = json!({
            "version": "native.artifact-input.v1", "mode": "bound",
            "collection": { "id": "collection", "kind": "folder" },
            "records": [{
                "id": "one", "type": "WorkItem", "kind": "task", "name": "One",
                "summary": null, "lifecycle": "active", "maturity": null,
                "persistence": "enduring", "facets": {}
            }]
        });

        let nested = render(
            "<div>{{type:'RecordCard',props:{record:props.input.records[0]},children:[]}}</div>",
            &input,
        )
        .unwrap_err();
        assert_eq!(nested.code, "mdx_output_invalid");

        let mutation = render(
            "{(() => { const node = <p>safe</p>; node.type = 'RecordCard'; return node; })()}",
            &input,
        )
        .unwrap_err();
        assert_eq!(mutation.code, "mdx_runtime_failed");

        let primordial = render(
            "{(() => { WeakSet.prototype.has = () => true; return <RecordCard record={{id:'one'}} />; })()}",
            &input,
        )
        .unwrap_err();
        assert_eq!(primordial.code, "mdx_runtime_failed");
    }

    #[test]
    fn compiled_cache_evicts_deterministically_and_admission_saturates_closed() {
        let _guard = test_guard();
        {
            let mut cache = cache().lock().expect("cache lock");
            cache.entries.clear();
            cache.bytes = 0;
            cache.clock = 0;
        }
        for index in 0..MAX_CACHE_ENTRIES {
            let key = format!("test-{index:03}");
            cache_insert(key.clone(), cache_entry(&key, format!("compiled-{index}")));
        }
        let first = "test-000";
        assert!(cache_lookup(first, &cache_manifest(first)).0.is_some());
        let extra = "test-extra";
        cache_insert(extra.into(), cache_entry(extra, "compiled-extra".into()));
        let cache = cache().lock().expect("cache lock");
        assert_eq!(cache.entries.len(), MAX_CACHE_ENTRIES);
        assert!(cache.bytes <= MAX_CACHE_BYTES);
        assert!(cache.entries.contains_key(first));
        assert!(!cache.entries.contains_key("test-001"));
        drop(cache);

        let permits = (0..MAX_BLOCKING_JOBS)
            .map(|_| try_admit().expect("capacity available"))
            .collect::<Vec<_>>();
        let saturated = try_admit().unwrap_err();
        assert_eq!(saturated.code, "mdx_resource_limit_exceeded");
        assert_eq!(saturated.details["phase"], "admission");
        drop(permits);
    }
}
