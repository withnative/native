# Artifact runtimes

The runtime-neutral host owns artifact identity, the exact optional `renders`
binding, Collection resolution, and `native.artifact-diagnostic.v1`. Runtime
adapters see only a resolved input envelope and return inert render plans. A
runtime failure never selects a fallback surface.

## Malleability model

An artifact separates three things that conventional applications often bind
together: durable data, authored presentation, and host authority. An author
can therefore present the same governed record world as a project Kanban, a
dashboard, or a visual bookshelf without copying those records into a
view-specific database. The artifact controls the bounded presentation; the
host resolves its deliberately named inputs and continues to mediate
authorization, writes, provenance, and audit.

This is a concrete capability rather than permission for an artifact to read
or change anything it can name:

- `native.mdx.v2` keeps the authored MDX as editable record text. It admits a
  closed component and interaction vocabulary over named inputs, including
  reusable exact-pinned modules. The host validates source and inputs, renders
  a safe tree, and reauthorizes mediated interactions when they are invoked.
- `native.html.v1` renders a self-contained HTML document over exact named,
  read-only inputs. It has no ambient network access, module import, or
  mutation surface.

In both runtimes, “all your data” can only mean records the caller is
authorized to read and has deliberately bound into that artifact. Input
bindings are explicit and source-pinned; presentation authority never becomes
workspace authority. A future system could use this separation to make larger
parts of the product shell user-authored, but whole-Workbench replacement is
directional rather than a shipped promise.

## `native.html.v1`

`native.html.v1` accepts a complete, self-contained authored HTML document and
delivers it only from the isolated artifact origin. Legacy documents retain the
zero/one `renders` input envelope. A document may opt into read-only named
inputs with one inert, exact-source declaration (either
`<script type="application/json" id="native-artifact-manifest">…</script>` or
`<meta name="native-artifact-manifest" content="…">`):

```json
{
  "schema": "native.html.artifact.v1",
  "inputs": {
    "records": {
      "envelope": "native.collection-envelope.v1",
      "required": true,
      "expose_to_root": true
    }
  },
  "capability_requests": [
    { "capability": "input.read", "scope": { "port": "records" } }
  ]
}
```

The closed declaration surface also admits `native.relation-envelope.v1`,
including a declared output schema and semantic relation dependencies for a
governed SQL query Collection, and `native.grouped-count-envelope.v1`. The
host revalidates this declaration against the exact current source attestation,
requires a matching source-pinned binding and exact artifact-source
`input.read` grant for every exposed port, then resolves all ports in one
authoritative snapshot. The delivered value is
`native.named-artifact-input.v1`; each envelope and the complete bundle carry
canonical digests and the bundle carries the content and authorization
revision. The browser bridge freezes the value and attests the ABI and sorted
port list in launch headers. Because JavaScript numbers and structured-clone
delivery cannot preserve arbitrary JSON integers, named HTML resolution fails
closed before hashing or delivery when any integer is outside
`[-9007199254740991, 9007199254740991]`; this applies to collection facets and
governed-SQL rows alike. HTML has no module imports, mutation surface, or
network authority. Historical governed-SQL relation execution is explicitly
unsupported and fails closed until a portable replay contract exists.

## `native.mdx.v1`

`native.mdx.v1` is genuine MDX source compiled and executed on the server. The
browser receives only `native.safe-tree.v1`; it never receives generated
JavaScript, evaluates source, injects raw HTML, or creates an iframe.

The release contract pins:

| Layer | Exact value |
|---|---|
| Compiler | `mdxjs-rs` / `mdxjs 1.0.4`, automatic JSX runtime |
| Compile profile | `native.mdx.compile.v1` |
| Compiler modules | `native.mdx.v1/jsx-runtime`, `native.mdx.v1/provider` |
| Executor | `rquickjs.quickjs-ng` / `rquickjs 0.11.0` |
| Executor profile | `native.mdx.quickjs.v1` |
| Component policy | `native.mdx.components@1` |
| Input | `native.artifact-input.v1` |
| Output | `native.safe-tree.v1` |
| Cache namespace | `native.artifact-compiled-cache.v1` |
| Adapter revision | `1` |

The MDX/SWC line needs a compatibility-only vendored `swc_common 12.0.1`.
`vendor/README.md` records the single source change. `serde 1.0.228` is also
exact because the current JWT dependency requires that line while SWC refers
to its versioned private facade. `Cargo.lock`, `vendor/`, the runtime descriptor
returned by `render_artifact`, and the checked-in fixtures form the release
source manifest for this adapter.

### Authority boundary

Every render creates a fresh QuickJS runtime and context with a 64 MiB heap,
512 KiB stack, deterministic interrupt budget, and emergency 500 ms deadline.
Before content runs, a temporary loader resolves only the two binary-owned
compiler modules above; the loader is then detached to deny every request,
including dynamic `import()`. There is no source-controlled module or host I/O
callback. The context has no Node/browser, network, database/tool,
filesystem/process/environment, storage, clipboard, crypto, clock, timer,
random, navigation, or mutation binding. Authored static and dynamic imports
and exports fail policy validation. The only input is a deep-frozen copy of the
host-resolved envelope exposed as `props.input`.

The global `eval`/`Function` bindings and the constructor properties for
ordinary, async, generator, and async-generator functions are replaced with a
frozen denial stub before their prototypes are frozen. This closes computed and
prototype-chain constructor recovery while leaving ordinary authored functions
usable.

Record components accept object identities from that envelope, not copied ids.
External `http(s)` links are canonicalized once by the Rust URL policy before
they enter the safe tree. The workbench parses that canonical value again,
requires an http(s) protocol with no credentials, and opens it only on a user
click with `noopener noreferrer`; record navigation is also attached by the host.
Images are small signature-checked PNG/JPEG/GIF/WebP data URLs. Remote images,
SVG, credentials, programmatic navigation, handlers, styles/classes, refs,
forms, raw DOM, functions, promises and arbitrary components are rejected.

### Safe-tree policy

The intrinsic set is `Fragment`, `h1`–`h6`, `p`, `span`, `div`, `section`,
`article`, `ul`, `ol`, `li`, `blockquote`, `pre`, `code`, `em`, `strong`,
`del`, `hr`, `br`, table elements, `a`, and `img`. Native components are
`Stack`, `Grid`, `Callout`, `Badge`, `Metric`, `RecordList`, `RecordTable`,
`RecordCard`, `Field`, and `EmptyState`. Props are checked per component in
Rust after the JavaScript bridge has already rejected non-data values and
fabricated record identities.

A field named by `RecordTable`'s `columns` or `RecordCard`'s `fields` must be a
scalar record field or a facet carried by at least one record — the table's own
bound list for a column, the whole canonical input set for a card. A record
that lacks it renders that field blank rather than refusing, which is what
makes these components usable over a heterogeneous collection where an open
facet is not uniformly present. A field no record in scope carries is still
refused, so a typo'd facet key fails the render instead of blanking everywhere.
`Field`'s single `field` prop is the exception: it is checked against its own
record alone, so naming a facet that record lacks refuses the artifact.

Limits are 524,288 UTF-8 source bytes, 10,000 input records, 8,388,608 input
JSON bytes, 64 MiB QuickJS heap, 524,288 stack bytes, 250,000 interrupt ticks,
a 500 ms emergency deadline, 10,000 output nodes, depth 64, 2,097,152 output
JSON bytes, and 262,144 bytes per decoded data image. Identical source,
descriptor and input produce the same canonical key-sorted safe tree or the
same diagnostic meaning.

### Validation, replay, cache and operations

Normal `create_record` and `update_record` calls validate prospective MDX in
the caller's write transaction before any event is appended. Validation parses,
applies the authored-module policy, compiles, and inspects the generated module;
it never executes. Replay/import stays pure: invalid historical source is
projected faithfully and fails closed on open.

The disposable in-process cache stores generated source and a digest-checked
manifest only. Hosted storage keys are principal-namespaced. It is
deterministically LRU-bounded to 64 entries and 32 MiB;
compilation never holds the global cache lock. Its key is length-delimited
SHA-256 over the fields listed in the ratified order (body digest,
runtime/compiler/profile/component/input/executor/output/revision). It never
stores inputs or output. A corrupt entry is deleted and compiled once; opens
report `miss`, `hit`, or `rebuilt_corrupt` in plan metadata. Compile/execute
work is admitted to a four-job blocking pool and fails closed when saturated.
The root source provenance captures the exact body-bearing event sequence and
bytes in one read, then reports record id, that event sequence, body digest and
source locations where available. This leaves the seam open for a future
dependency closure without changing v1.

Structured diagnostics never contain full source, generated JavaScript, input
records or raw QuickJS stacks. Every adapter diagnostic includes artifact id,
runtime/revision, body digest, and a bounded source range. Compiler points are
clamped to the authored source; failures without a normalized source map use
the defensible whole-root-source range rather than a generated-JS location.
The stable MDX codes are
`mdx_source_too_large`, `mdx_policy_violation`, `mdx_compile_failed`,
`mdx_unknown_component`, `mdx_runtime_failed`,
`mdx_resource_limit_exceeded`, `mdx_capability_denied`,
`mdx_output_invalid`, `mdx_cache_corrupt`, and
`unsupported_runtime_revision`.

The engine also retains a content-free operational snapshot: aggregate
attempt/failure, cache, denial, limit and latency counters plus the latest 128
validation/render observations. Each observation is bounded and contains only
artifact id, runtime/revision, a 12-character body-digest prefix, stage
durations, cache state, input counts/bytes, output nodes/bytes, and diagnostic
phase/code/limit. Source, input values, generated code and record content are
never collected. native-ce intentionally has no process-wide log/metrics
backend; a hosting exporter polls `artifacts::mdx_telemetry_snapshot()` and
translates this internal seam to its configured logs and metrics backend.

Any compiler/transitive lock, executor, profile, component policy, envelope,
safe-tree, limit or adapter-code change requires an adapter-revision and cache
namespace review. Removed syntax, incompatible props/components/output, new
authority/import behavior, or mutation requires a new runtime major rather
than silently changing `native.mdx.v1`.

## `native.mdx.v2` reusable modules

V2 is additive: v1 compilation, imports, bindings, cache namespace, and
descriptor are unchanged. A reusable source is a governed `Program
kind:module`; its body remains an editable draft until `manage_mdx_modules`
publishes the exact current source event and digest. Publication preallocates a
portable event UUID, verifies the complete dependency closure in one
transaction, and records an immutable `native.module-release.v1` descriptor.
Deprecation is advisory. Withdrawal makes every exact consumer fail closed and
never redirects it to replacement bytes. Deprecate and withdraw are
compare-and-set operations over the exact status event sequence returned by
inspection, so a stale reviewer cannot overwrite an intervening lifecycle
decision.

The v2 adapter revision is exactly `8`. Its descriptor, release runtime
contract, compiled-graph key, parsed-source key, validation errors, render
diagnostics, and operational observations all derive that value from the same
binary constant. V2 cache entries use the
`native.artifact-compiled-cache` namespace with the adapter revision as an
explicit key field, so a revision change cannot reuse prior parsed or compiled
entries. New publications record revision 8 and component policy 3. Revision 8
adds the fixed record-relation input described below. The loader also recognizes
four exact historical release contracts. Revision 7 retains component policy 3
and the revision-7 Collection/grouped-count input surface, but does not gain
relations retrospectively. Revision 6 uses the
pinned historical compiler-lock digest and component policy 2; it includes the
facet grouped-count axis but not `PlacementPreview`. Revision 5 uses the same
compiler-lock digest and component policy 2; it admits
Collection inputs and grouped-count inputs over the closed `record.kind` axis,
but not the revision-6 facet axis. Revision 4 uses the same historical digest
with component policy 1 and admits Collection inputs only, so it has neither
grouped counts nor `BarChart`. Immutable releases published under any supported
historical contract remain live and replayable. No other historical runtime
tuple, and no input declaration newer than a release's own surface, is
accepted.

Imports accept only:

```text
native:module/<lowercase UUID>@event-<lowercase UUID>?sha256=<64 lowercase hex>
```

The resolver verifies publication/source event identities, source and release
digests, status, interfaces, explicit port mappings, one release per stable
module, acyclicity, and the ratified closure quotas before starting QuickJS.
There is no relative, package, name, CDN, floating, or fallback resolution.
The verified in-memory loader exists only while the already-resolved graph is
declared; execution still receives no Node, browser, network, filesystem,
process, storage, clock, random, database, or tool authority and returns only
the existing Rust-validated `native.safe-tree.v1`.

Both module and root manifests are statically extracted JSON-literal exports:
`native.mdx.module.v1` and `native.mdx.artifact.v2`. Named artifact ports bind
through `manage_artifact_inputs` to governed Collection query, selection, or
folder records. The host resolves each Collection into a branded, frozen
`native.collection-envelope.v1`; module wrappers expose only explicitly mapped
ports through their hidden `native.inputs` argument. A port may instead declare
the closed `native.grouped-count-envelope.v1` projection over either
`record.kind` or an authored facet axis such as
`{ "kind": "facet", "key": "status" }`. The facet key is declared by the
artifact input itself; it need not also appear in schema configuration. Keys
use the same nonblank, control-free, 128-byte contract as other authored facet
references. Facet values come from the canonical records in the authorized
cohort: string values name buckets, a missing or null value contributes to the
`null` bucket, and any other value refuses the render. The host derives all
bounded, deterministically ordered integer buckets from the same caller-visible
Collection cohort inside the pinned render snapshot;
projection ports never enter the global record set or an interaction's
`bound_input` domain. The root's authored `props.input` contains only records
and envelopes exposed by its own exact `input.read` grants. Module-only inputs
exist solely in that release's scoped, hidden `native.inputs` context; they are
not available for the root to borrow through the global input object. Render
provenance still receipts the complete governed delivery. Missing, ambiguous,
undeclared, unused, or incompatible bindings fail before module execution. The
reserved v1 zero-or-one `renders` binding remains unchanged.

A port may opt into the fixed `native.relation-envelope.v1` instead of the
legacy Collection envelope. This is not an author-defined query or field
projection: its complete `relation.rows` array is the exact existing artifact
record shape (`native.artifact-record.v1`) resolved for that Collection, in the
same deterministic order and with the same canonical digest as the legacy
envelope. The closed envelope identifies the Collection and its binding and
pinned content revisions, declares record grain with stable key `id`, and carries
`extent: { complete: true, returned, total }`. The host and runtime both fail
closed above 10,000 rows or 8,388,608 canonical row JSON bytes, and the runtime
validates shape, extent, stable-key uniqueness, and digest before authored code
runs. Relation rows authenticate `RecordList`, `RecordTable`, `RecordCard`,
`Field`, and user-gesture record navigation. They deliberately do not enter a
write interaction's `bound_input` domain; relation mutation is outside revision
8's surface. Authorization, hidden-record filtering, atomic snapshot resolution,
module scoping, receipts, cache hydration, and historical replay use the same
host boundaries as other named inputs.

V2's component policy is `native.mdx.components@3`. It retains the authenticated
`BarChart` primitive: authored code must pass the exact grouped-count envelope
object supplied by the host, not a copied or fabricated series. The runtime
revalidates the envelope digest, total, bucket ordering, integer counts and
resource bounds before emitting a closed safe-tree chart node. The browser owns
the accessible labels and progress presentation; the primitive grants no SVG,
HTML, style, callback, navigation, or per-bar interaction authority. V1 remains
on `native.mdx.components@1` and does not admit `BarChart`. The chart root is a
host-owned lower boundary of the authored CSS scope, so type selectors in an
artifact stylesheet cannot restyle or hide its React-owned descendants.

Policy 3 also adds the inert structural `PlacementPreview` component for
writable artifacts. It is an already-evaluated, record-specific alternative
representation, authored directly under the target that owns it:

```mdx
<DropTarget entry="do_now">
  <PlacementPreview recordId={task.id}>
    <span class="priority-dot"><Field record={task} field="name" /></span>
  </PlacementPreview>
  {/* ordinary target content */}
</DropTarget>
```

`recordId` must name a canonical record from the resolved input. A preview must
be a non-empty direct `DropTarget` child and is unique by record within that
target. It emits no wrapper element and therefore accepts no author class of
its own. Authored MDX evaluates once on the server: the browser may select the
matching serialized subtree, but never receives a function or template to
evaluate. Preview variants and descendants consume the existing global
safe-tree limits of 10,000 nodes, depth 64, and 2 MiB serialized output.

Policy 4 adds the closed `RecordCreate` control and the general
`record.create` interaction effect. Creation is declarative rather than a
forwarded `create_record` call: the manifest fixes or bounds every part of the
new record, while the invocation carries only values for declared person or
bound-record inputs. For example, a folder-backed work slate can declare:

```mdx
export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    tasks: {
      envelope: "native.collection-envelope.v1",
      required: true,
      expose_to_root: true
    }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "tasks" } }
  ],
  interactions: [{
    id: "create_task",
    label: "Create task",
    effect: "record.create",
    create: {
      destination: { from: "bound_input", port: "tasks" },
      shape: {
        type: {
          source: { from: "literal", value: "WorkItem" },
          domain: { kind: "enum", values: ["WorkItem"] }
        },
        kind: {
          source: { from: "literal", value: "task" },
          domain: { kind: "enum", values: ["task"] }
        },
        fields: {
          name: {
            label: "Title",
            source: { from: "input", input: "title" },
            domain: { kind: "string", min_length: 1, max_length: 200 }
          },
          lifecycle: {
            label: "Status",
            source: { from: "input", input: "status" },
            domain: { kind: "enum", values: ["open", "in_progress"] }
          }
        },
        facets: {
          stream: {
            label: "Stream",
            source: { from: "input", input: "stream" },
            domain: {
              kind: "enum",
              values: ["native", "supercritical", "personal"]
            }
          }
        }
      }
    }
  }]
}

<RecordCreate entry="create_task" />
```

The destination is either a fixed record id or the root Collection bound to a
named input port; it is never supplied by the invocation. A value source is a
manifest `literal`, a host-owned person `input`, or a record selected through a
declared `bound_input` slot. Its separate domain is one of a finite `enum`, a
bounded `string`, a bounded `number` with optional step, `boolean`, bounded
`date` or RFC 3339 `datetime`, a named `bound_input` cohort, or one bounded
non-nested `list`. Lists remain unavailable unless the current governed record
shape and ordinary creation transaction admit a multi-valued property. Boolean
controls likewise remain fail-closed for properties whose governed persistence
shape has no boolean representation.

`RecordCreate` is a void, host-owned semantic primitive: it accepts only the
entry id, no authored children or class, and renders accessible controls from
the declared labels and domains. Submit sends scalar/list person inputs in the
invocation's `values`, bound-record selections in `slots`, no destination,
actor, owner, authorization, attribution, id, or reason, and no facet
compare-and-set observations. Cancellation before submit writes nothing. The
host re-resolves the current source and bindings, validates every value and
reference, intersects the declaration with current schema and permission,
derives identity/provenance, and runs the ordinary governed record-creation
transaction. Initial fields and facets therefore commit atomically.

The invocation idempotency key is scoped to the authenticated actor, artifact,
entry, and exact source revision. Repeating an uncertain submission returns the
same authoritative record instead of creating a duplicate; reusing the key for
a different resolved intent is rejected. A committed result carries that record
under `refresh.record`; the workbench refreshes the bound input and reconciles
only to that authoritative render. Undeclared values, stale source digests,
out-of-domain values, records outside a named bound port, non-Collection or
unauthorized destinations, and specialized record shapes which require a
different governed atomic workflow are unavailable or rejected without a
write. There is no task-specific `NewTask` operation, artifact-defined
JavaScript validation, expression language, query-backed destination, or
workspace-wide value lookup in this contract.

For an interactive v2 render, the plan also carries host-owned
`interaction_availability`: sorted `supported_entries`, `editable_records` and
`records_by_port`, plus bounded `record_labels` for referenced controls when
needed. The manifest's existing bound-input slot selects the
relevant port; an unscoped slot uses their union only when every resolved bound
port (including non-record envelopes) is root-readable under the exact source
grant. Private/module-only port cohorts never enter
`interaction_availability.records_by_port` or `editable_records`. The host
derives editability through the canonical bulk authorization fold on the
render's authority footing. The
shape participates in semantic render identity, while compare-and-set token
values remain excluded. It is omitted for inert and v1 plans. Availability is
only a snapshot affordance: release still re-resolves the exact source and
entry, validates domains/schema/value rules and CAS, and reauthorizes inside
the write transaction.

Every module release freezes its direct capability requests, and every root
artifact source event has its own requests. Initial v2 supports scoped
`input.read` plus user-gesture record and external navigation; arbitrary live
query and mutation are denied. A grant names one exact subject union:
`module_release` identifies a module record, publication event, and source
digest, while `artifact_source` identifies the root artifact record, source
event, and source digest. Root `input.read` grants name only the declared
artifact port; module grants name the declared module port and its mapped
artifact port. The grant spells those ports differently from the manifest that
declares them, because through an import they are genuinely different ports: a
manifest declares `scope: { port }`, while a grant scope is
`{ artifact_port }` against `artifact_source` and
`{ module_port, artifact_port }` against `module_release`. Copying the
manifest's `port` into a grant is refused, and the refusal says so. Effective authority requires the subject's exact request,
current opener authority, and runtime support. Grants do not transfer to a
later source or publication event, so an edit or upgrade with new or broadened
authority cannot activate silently. The one exception carries authority forward
without broadening it: when a body edit leaves the declaration surface digest
unchanged, each existing grant is re-issued against the new exact source only if
that source still requests the identical capability and scope, and is dropped
and reported otherwise. A publication upgrade never carries. Record consumption
authorization remains independent from runtime grants.

V2 compilation is a forward-command concern, never a projector concern.
Publication records a canonical release descriptor. Every forward v2 artifact
create or source-changing update also emits an immutable
`artifact.source_attested` companion event in the same transaction, after the
exact body-bearing source event and runtime facet. Its hash-bound descriptor
freezes the companion event identity, source event identity and digest, root
ports, ordered exact imports, `module_inputs`, and capability requests. Input
and grant events bind that source-attestation identity as well as their exact
declaration, request, and complete port-mapping path. Replay/import verifies
closed shapes, identities, ordering, hashes, and dependency descriptors already
folded from earlier events; it does not parse, compile, or execute authored MDX
or JavaScript. Render fails closed if its current exact source has no companion,
and ignores bindings or grants issued for an older source. In particular, an
`input.read` grant for a transitive module must attest every exact forwarding
edge from that module port through its parents to the named root artifact port.
A missing, invented, or changed edge fails closed.

Content shape, source identity, and release closure are checked against the
same immutable content-log snapshot used for resolution. Record visibility is
checked separately against live caller authority through the read lens, because
authorization policy is not replayed into historical snapshots. Input-bundle
receipts bind both the content boundary and the authorization revision. A live
render observes both through one database snapshot; a historical render fences
the current authorization revision before and after resolving every port and
fails with a content-free diagnostic if it changes. Both checks happen before
capability preflight or compilation. In a local deployment,
selecting the database is the ownership boundary. On hosted HTTP,
authentication and database-membership authorization happen before `Caller` is
constructed and routed to that database; the runtime rejects incomplete hosted
context and requires the root artifact, every exact module subject, and every
bound Collection to remain visible to the caller. Runtime capability grants
never substitute for database or record consumption authority.

The graph limit is 128 modules, depth 32, 512 dependency edges, 1,024 public
exports, 4 MiB aggregate source, and 16 MiB compiled JavaScript. The compiler
and executor remain exactly `mdxjs 1.0.4` and `rquickjs 0.11.0`; the cache and
descriptor use the v2 namespaces and include the portable dependency closure
digest. Render provenance lists every exact module/source publication. Stable
module, binding, grant, status, resolver, and capability failures use
`native.artifact-diagnostic.v1` and never select another runtime or surface.
Runtime attribution is carried by an engine-owned channel hidden before
authored code runs; authored `Error.stack` text is never parsed. The channel
tracks exception identity across exact wrapper edges, so rethrows keep the
deepest causal module while a caught failure cannot taint a later independent
failure. Ratified origins include the exact module record, publication/source
identities and digests, export name, authored source range, and canonical import
chain.

`manage_mdx_modules impact` walks the replayable immutable release-edge
projection transitively, then joins live root artifact source snapshots to the
impacted publication set. Root results carry their exact source event, source
digest, and direct impacted pins, so upgrade review is based on reproducible
dependency evidence rather than a best-effort text search.

`render_artifact.as_of` accepts a content sequence, timestamp, or portable
event ID. Historical responses are explicitly labeled and report whether the
offline graph was complete. Event-ID boundaries remain meaningful when an
import remaps local sequence numbers; source/publication IDs and digests, not
local sequence numbers, are the portable identities.
For a historical v2 render, admission happens before scratch database creation,
schema setup, or replay. One permit is held across exactly one replay and the
subsequent render; the already-materialized snapshot path cannot acquire a
second permit or replay again.
