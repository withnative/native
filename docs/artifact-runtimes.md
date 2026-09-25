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
  read-only inputs. It has no ambient network access or module import. The
  runtime is `native.html.v1` either way; what changes is the declaration:
  `native.html.artifact.v1` admits no mutation surface, while
  `native.html.artifact.v2` declares the same typed `interactions` entries
  as MDX v2, settled through the commit-on-gesture surface described below.

In both runtimes, “all your data” can only mean records the caller is
authorized to read and has deliberately bound into that artifact. Input
bindings are explicit and source-pinned; presentation authority never becomes
workspace authority. A future system could use this separation to make larger
parts of the product shell user-authored, but whole-Workbench replacement is
directional rather than a shipped promise.

What an already-open artifact does when its bound records change, per
runtime and with the tests that prove it, is stated in
[artifact-open-view-promise.md](artifact-open-view-promise.md).

## One Collection, two authored views

Suppose a governed Collection contains the tasks for a launch. Create
two `Document kind:artifact` records with `facets.runtime: "native.mdx.v2"`.
Each body starts with this same declaration, followed by one of the view
fragments below:

```mdx
export const nativeArtifact = {
  schema: "native.mdx.artifact.v2",
  inputs: {
    items: {
      envelope: "native.collection-envelope.v1",
      required: true,
      expose_to_root: true
    }
  },
  module_inputs: {},
  capability_requests: [
    { capability: "input.read", scope: { port: "items" } },
    { capability: "navigation.record.user_gesture", scope: {} }
  ]
}
```

The first body presents a compact table:

```mdx
# Launch tasks

{native.inputs.items.records.length
  ? <RecordTable records={native.inputs.items.records} columns={["name", "summary"]} />
  : <EmptyState title="No visible items" />}
```

The second presents the same records as a grid of cards:

```mdx
# Launch overview

{native.inputs.items.records.length
  ? <Grid columns={3} gap={3}>
      {native.inputs.items.records.map(item =>
        <RecordCard record={item} fields={["name", "summary"]} />)}
    </Grid>
  : <EmptyState title="No visible items" />}
```

For **each artifact**, call `manage_artifact_inputs` with the following
arguments, substituting its artifact ID and the same Collection ID:

```json
{
  "action": "bind",
  "artifact_id": "<artifact UUID>",
  "port_name": "items",
  "collection_id": "<launch Collection UUID>"
}
```

Then call `manage_artifact_module_grants` with
`{ "action": "read", "artifact_id": "<artifact UUID>" }` to inspect that
artifact's exact source subject. For its `input.read` request, grant using the
returned `subject_event_id` and `source_sha256`:

```json
{
  "action": "grant",
  "artifact_id": "<artifact UUID>",
  "subject_kind": "artifact_source",
  "subject_record_id": "<artifact UUID>",
  "subject_event_id": "<source event UUID from read>",
  "source_sha256": "<source digest from read>",
  "capability": "input.read",
  "scope": { "artifact_port": "items" }
}
```

Issue a second grant against the same subject with
`"capability": "navigation.record.user_gesture"` and `"scope": {}`.
The record components require this declared and granted navigation capability;
it lets the host open a record on a person's click. Finally, call
`render_artifact` with `{ "id": "<artifact UUID>" }` for each artifact.
The placeholders above stand for actual IDs and digests, not literal values.

Both views read canonical objects from `native.inputs.items.records`. Neither
stores its own copy of the launch tasks. Given the same content snapshot and
caller authority, both resolve the same cohort; later opens reflect changes to
the governed records. Different callers can see different authorized subsets,
and separate live renders can observe different revisions.

The presentation is reusable because it names the `items` contract, not the
launch Collection ID. To show another project, bind an artifact's
`items` port to an authorized project Collection that resolves the same
`native.collection-envelope.v1` contract. These fragments use only the standard
`name` and `summary` fields, so they do not depend on a launch-specific facet.
A view that uses custom facets also depends on those facets being present in
the relevant record scope. A governed-SQL relation is a different contract:
changing the bound Collection does not turn these `.records` expressions into
`.relation.rows`, or satisfy a relation's declared schema and semantic versions.

Reuse does not share authority: a second artifact needs its own bindings and
exact-source grants. Reusable MDX modules apply the same idea to shared
presentation code through exact publication pins and explicit port mappings,
as described below. Adding editing controls requires a declared, supported MDX
interaction that the host validates and reauthorizes on invocation. An HTML
version declaring `native.html.artifact.v2` acquires that mutation surface
through typed interactions; one on v1, or with no interaction declaration,
stays read-only.

The [artifact row of the capability map](capability-map.md) links the selected
runtime policy and executable evidence for named inputs, exact-source grants,
record components and compatible input resolution.

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
governed-SQL rows alike. `native.html.artifact.v1` documents have no module
imports, mutation surface, or network authority. Historical governed-SQL
relation execution is explicitly unsupported and fails closed until a
portable replay contract exists. The host
performs no wall-clock liveness polling of the frame: it arms a
bootstrap-handshake timeout and one bounded acknowledgement wait per in-place
input delivery, and nothing else. The frame announces a non-persisted `pagehide`
over the bridge, and the host answers that announcement by requesting a fresh
launch, because a reloaded frame lands on a consumed one-use ticket and can
neither bootstrap again nor be observed by any host-side timer; only repeated
reloads fail shut with a diagnostic.

A booted document may subscribe to later input deliveries with
`nativeArtifact.onInput(callback)`; `nativeArtifact.input` reads the bundle
currently held. When a refresh resolves a different input digest under the
same body digest, the host posts the new frozen bundle, its digest, and its
revision over the existing bridge port instead of replacing the frame, at
most once per digest. An ordered delivery is always answered: `input-applied`
once every subscriber has run — including idempotently when the digest is one
the bridge already holds — or `input-unhandled` with a reason when it cannot
be applied (`no-subscriber`, `subscriber-threw`, `stale` for a sequence that
does not advance under a different digest, `freeze-failed` when the bundle
cannot be frozen). A message that fails the trust checks (wrong bridge
version, arrival before initialisation, a non-string digest, or a non-number
sequence) is dropped silently, and the host's bounded wait then relaunches.
Any answer other than `input-applied` within that one bounded wait, or a
changed body digest, replaces the frame with a fresh one-use launch exactly
as before.

A document may also hand its own view state to the frame that replaces it.
`nativeArtifact.setViewState(value, { schema })` publishes eagerly: the value
must survive a pristine JSON round-trip inside the same 65536-byte bound as an
intent, the optional `schema` is an advisory intent id, and a violation is a
synchronous `TypeError` at the call site rather than a silent loss. Publishes
are coalesced to at most one posted message per animation frame, latest wins,
and before the port opens a waiting view state occupies one reserved slot in
the 32-slot queue rather than accumulating. There is deliberately **no
acknowledgement and no bounded wait**: no host decision rides on this message,
so unlike input delivery it adds no wall-clock liveness surface, and a lost
publish simply means the successor cold-boots. The host holds one opaque blob
per artifact identity, in memory, never inspecting `value` — it influences no
digest, no authorisation decision and no render decision — and stamps it with
the body digest that published it rather than trusting the frame for that. The
blob survives a body-digest relaunch and the reload-recovery path, and is
cleared with the hold on a settled refusal or denial, on an artifact identity
change, and on unmount. The successor receives it as an optional `view_state`
field in `native-html-init`, deep-frozen and exposed as
`nativeArtifact.viewState` and in the `ready` resolution, carrying `value`, the
advisory `schema`, and `from_body_digest`. **`schema` is the evidence a
successor can act on** when deciding whether it understands what it was handed.
`from_body_digest` names the body that published the blob, but the init message
does not tell a document its own body digest, so a successor has nothing to
compare it against: treat it as provenance for the host and for debugging,
not as something authored code can branch on. Restoration is the author's
responsibility and best-effort by construction. Because the successor body can
read whatever the predecessor published, **view state is for view state**:
authors must not put secrets or unsaved user content in it. The verifier
harness never sends one, so `nativeArtifact.viewState` is always `undefined`
under verification, which is always a cold boot.

The message set is additive under `native.html.bridge.v1`; a document that
never subscribes and never publishes sees no change in behaviour. The
host-mediated navigation message carries the gesture disposition the same
additive way: `newTab: true` when the trusted in-frame click held
Ctrl/Cmd or was a middle-click, absent for a same-tab click. The host
refuses any other disposition shape, keeps the existing user-activation and
destination checks, and still resolves the named record under the viewer's
own authenticated read — naming a record never preauthorizes it.

### HTML write settlement (`native.html.artifact.v2`)

A v2 document declares typed `interactions` — the same shape as MDX v2 — in
the existing inert manifest element, requests `input.read` per exposed port
(there is no separate write-proposal grant), and proposes declared writes
from authored JavaScript with `nativeArtifact.propose()`. A newer proposal
supersedes an older one still awaiting review; only a write already being
applied cannot be torn down. The host
supplies artifact and source identity, observed compare-and-set versions, and
idempotency; none of those belong in the proposal.

Settlement is commit-on-gesture with the Apply tray as the fallback. Two
layers gate the ungated path. The frame runtime marks a proposal
gesture-backed only when it is made during dispatch of a terminal trusted
gesture event (`click`, `drop`); the host additionally requires its own
`navigator.userActivation`. The mark is necessary and never sufficient. A
declared, in-scope, reversible write then commits on the gesture,
optimistically, with no Apply step. Everything else keeps the Apply step: a
proposal made outside a completed gesture still reaches the host and routes
to the tray — it does not throw and is not silently dropped — as does any
proposal where `userActivation` is unsupported, which degrades to the tray
rather than failing. A proposal outside the declaration is rejected with a
brief reason, never escalated to a dialog.

A write committed on the gesture leaves a host-owned settled-change trace
rendered outside the artifact's layout, carrying a real reversal: the
reversal goes through an ordinary declared entry with the commit's
compare-and-set token and reports a conflict rather than overwriting. A
write committed through the Apply tray leaves no trace; the host shows a
transient notice instead. Effects with no derivable inverse keep their
Apply step — record creation has no inverse the artifact can assert, so it
stays gated — and therefore never become traces at all. A trace can still
carry a disabled reversal: when the commit returned no post-write version
to check against, or when a later declaration change removed every entry
able to assert the prior value, the reversal is disabled with a plain
reason.

Reversibility is resolved against the value the write replaced, which has a
consequence worth knowing before authoring: **a `facet.set` on a facet that
can be absent needs a `facet.unset` declared on the same facet, or a write
replacing an absent value is not reversible.** Only a `facet.unset` entry can
assert an absent prior value, so without one the inverse of "absent becomes
set" does not exist, the write is not `immediate`, and it routes to the Apply
tray even though the artifact and the gesture are both valid. The prior value
is read per record, so this is the first write to a *given* record's facet,
not one first write overall.

The same resolution decides every later write. One replacing a present value
commits on the gesture when a declared `facet.set` can assert that value — so
for a toggle-shaped facet, whose declaration covers everything the facet can
hold, the symptom is a tray that appears only the first time. A facet holding
a value that came from outside the declaration — a direct edit, another
artifact, a creation default — keeps routing to the tray until it holds a
covered value, however many writes in.

Two adjacent constraints show up in the same place. A declared facet value
must be a string, number or object: booleans are refused, because the stored
form has no representation for one, so a boolean-ish facet carries `"true"`
and `"false"` as strings. And a `facet.unset` entry declares no value at all,
since it has none to write, nor any value slot — anything but its one
`bound_input` record slot is refused as declared but unused.

Two boundaries are not obvious. Relation-envelope rows never enter a write
interaction's `bound_input` domain, so a governed-SQL-fed view cannot be
written through; writable slots require Collection-envelope inputs.
Engine-dispatched facet keys (`archived`, `runtime`) and `owner` are not
writable through an interaction at all: declaring them is refused outright
rather than gated through the tray. `Annotation`/`comment` creation is
refused as a specialized governed workflow. Known limits: a pointer-event
drag producing neither `click` nor `drop` cannot arm a proposal, and a
widget proposing only from `keydown` never earns the gesture mark, so both
settle through the tray at best.

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
durations, cache state, input counts/bytes, output nodes/bytes, diagnostic
phase/code/limit, and a per-port split keyed by author-declared port
identifiers (kind, cache state, and microsecond counters only). Source, input
values, generated code and record content are never collected. native-ce
intentionally has no process-wide log/metrics backend; a hosting exporter polls
`artifacts::mdx_telemetry_snapshot()` and translates this internal seam to its
configured logs and metrics backend.

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

Live Collection-port envelopes are also held in a process-global, bounded
in-memory cache (compile-time entry count and total bytes; LRU eviction; never
persisted). The key includes origin database id, collection id, port-declaration
identity, caller principal fingerprint (the same digest as `caller_sha256`),
the pinned `snapshot_event_id` and `snapshot_event_seq`,
`authorization_revision`, a content-free `meta_sha256` over the ordered rows of
`schema_config`, `vocabularies` and `vocabulary_values`, the port's
`binding_event_seq`, and the server build/adapter revision. Seq and epoch can
rewind after a backup restore or workspace re-adoption under the same
`origin_db_id`; the head event UUID keeps those coincidences from reviving a
stale envelope. Schema-config and vocabulary writes move neither the content
head nor the authorization epoch, so `meta_sha256` is what makes those
envelopes unreachable. An entry is therefore unreachable after any content,
authorization, meta-tier, or binding change; historical (`as_of`) renders and
governed-SQL relation ports never consult it. Legacy record-relation and
grouped-count ports are neither re-executed nor cached on a successful
`revalidate`; they are skipped by determinism under an unchanged head, epoch,
and meta digest. Other DIRECT-WRITE tables (`blobs`, `jobs`, `read_log_calls`,
hosted `bindings`, `derivation_requests`) are not read when assembling a
Collection-port envelope. `database_identity.origin_db_id` is part of the key
itself. A cache hit restores the exact envelope that previously entered the
input bundle.

`render_artifact` accepts an optional `revalidate` object: the previous live
`native.mdx.v2` `plan.provenance.revalidation` token plus `ports` copied from
`input_bundle.ports`. The token is
`{ artifact_id, snapshot_event_id, snapshot_event_seq, authorization_revision,
cache_key, caller_sha256, meta_sha256 }`. Unknown extra keys are ignored.
After the artifact read and authorization fence inside the pinned transaction,
any doubt — `as_of` present, a missing or malformed field, an unknown port, a
cache-key mismatch, a different content head (event id or seq) or authorization
epoch, a missing or different `caller_sha256` or `meta_sha256`, an
`artifact_id` that is not the requested artifact, or a non-v2 runtime — falls
through to a full render rather than an error. Otherwise Collection ports are
skipped (they cannot change without the head, epoch, or meta digest moving) and
every governed-SQL relation port is re-executed. Matching row and output-schema
digests yield `status: "rendered"` with `unchanged: true` and a slim plan:
`kind`, `version`, provenance of the verified fields only (no `render_sha256`,
no `input_bundle.ports`), `cache.state: "unchanged"`, and timing if requested.
No tree, interactions, observed tokens, interaction availability, or styles.
A mismatch reuses any relation envelopes just executed and returns a full tree
with `cache.state: "revalidated_full"` and a content-free
`cache.revalidation.miss` of `artifact`, `head`, `authorization`, `cache_key`,
`caller`, `meta`, `relation_port`, or `malformed`. Execution-receipt-only
differences (`observed_at`, snapshot token) are not a relation change; a query
such as `strftime('%Y-%m-%dT%H:%M:%fZ','now')` that actually changes rows
therefore takes the full-render path, which is then cheap because Collection
ports hit the in-memory cache.

Every live v2 render's provenance includes `caller_sha256`: SHA-256 of the
origin database id plus the authorization principal (trusted-local bypass,
membership, and account id). It is content-free, lives on the revalidation
token, and is repeated next to `render_sha256` on a full plan. The
compiled-graph cache (`plan.cache.key`) is unchanged: it still keys parsed
source and the module closure, not resolved inputs.

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
without broadening it: when a body edit leaves a port's declaration unchanged,
each binding and grant on that port is re-issued against the new exact source
only if that source still requests the identical capability and scope, and is
dropped and reported otherwise. A grant naming no port (user-gesture
navigation) carries whenever its request is still declared, regardless of input
changes; a changed port drops only its own binding and grants, and adding a
port drops nothing. A publication upgrade never carries. Record consumption
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
second permit or replay again. Combining `as_of` with `revalidate` always
takes the full historical path; the short-circuit is live-only.
