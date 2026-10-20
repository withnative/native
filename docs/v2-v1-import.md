# Probe v1 snapshot importer (HQ cutover S4)

Build and run the gated example:

```sh
cargo run --release --features v2-kernel-probe --example v2-import -- \
  --source /private/snapshot.db --target /private/new-v2.db \
  --seed RECORD_ID --seed-file /private/additional-ids.txt \
  --members-file /private/live-members.txt \
  --report /private/new-report.json
```

Seed files contain one ID per line. Seeds are explicit: expand relationship
neighbors into that file if wanted. The importer adds placement ancestors and
policy anchors, up to `native:root`. It opens the source read-only and keeps a
single SQLite read transaction throughout the import. The target must be new;
`--resume` admits a target from the same source database identity. Use the same
snapshot and members roster on retries. On every resume, pass the full seed set (including all previously imported seeds); an expanded full seed set can complete a partial subset. Record
and legacy snapshot receipts are idempotent; changed snapshots refuse instead of
silently updating imported identities. Setup/package and policy acts can be
repeated on resume. A report path must be new on every invocation.

The first supplied roster is frozen as a sorted set in a sealed target metadata
event, before any policy writes. On resume, reordered/duplicate lines are allowed;
changed account sets refuse without appending any target events. The JSON report's
`roster_change.added` / `removed` fields and the CLI error name the changed account
IDs. Deliberate roster changes require a separate operation; this importer does
not replace the frozen roster.

The roster requirement depends on the selected subset: a run whose in-scope
policies do not use members can omit `--members-file`. The target records that no
roster was supplied. A later expanded subset may require `--members-file` and
freeze its first supplied set, including an explicitly empty set.

Targets created by `b665ebe` cannot resume with this version; recreate them.
Targets that already imported policies without roster metadata (including
`3da2fcda3` targets) also require recreation because their exact previous roster
cannot be recovered safely. Fresh targets and setup-stage targets with no prior
import policy/home/record effects can initialize the metadata safely.

The command exits nonzero for refusals or review items. Unsupported links are
counted separately, as are links whose endpoints are outside the imported subset.
Reports contain IDs, type/kind counts and fixed diagnostic reasons, never titles,
bodies, excerpts, notes or facet values. Early fatal errors produce a redacted
refusal report; the target may be partial. Preserve private targets/reports outside
the repository.

## Identity, placement and authority

Records retain v1 IDs. UUID records use S1's existing creation event; named IDs
use the sealed `kernel.import_record_created.v1` event. Both carry the complete
current import state in the same host act. The public append seam refuses the
new event, and ordinary record creation still requires UUIDs. Synthetic provenance
receipt IDs use a separate fixed UUIDv5 namespace, leaving actual v1 event IDs
available for later history replay.

Foci slots provision homes and records as separate identities; they do not supply
a generic record-backed-home mapping. Each v1 record acting as a home therefore
gets a UUIDv5 derived home in a fixed namespace. `native:root` maps to
`kernel:root` and is not imported as a record. The home event records the source record ID explicitly, so the reverse mapping
exists even before that record is imported. Home creation is sealed, attributed
to the import host, validates collisions and owner principals, and is retryable.
The report's `homes` map and sealed home events record provisioned mappings. Snapshot provenance always records the deterministic prospective `derived_home` for every record, independently of seed choice; this is set even if the record never becomes a home and does not imply provisioning. The authorized
`v1_import::placement_as` read adapter resolves the current home to its v1 folder ID (including later rehomes) alongside
the actual kernel home ID.

V1 can attach an explicit replacement policy directly to a record. V2 policies
live on homes. Such a record is placed inside its own derived policy home, whose
parent is its original placement home. This protects the folder record itself as
well as its children. Original placement remains in provenance and the read
adapter, rather than being confused with that policy boundary.

Canonical v1 `account` bindings map to principals whose `auth_binding` is exactly the bare account ID. This matches KernelV2 `Caller::credential()` and stdio `--account ACCOUNT_ID`; no importer prefix is used. Source identity is retained separately in an agent marker bound to `v1:<origin_db_id>:import-source`, checked on resume. Earlier experimental targets with prefixed account bindings require a fresh import. Exactly one verified account for an owner
maps directly. Unknown/ambiguous owners default to the workspace administrator only if v1 authorization already gives that account visibility. Otherwise they require review and are not imported with that owner. Source owner IDs and binding evidence are retained and assumptions reported.
An exclusive account-only private policy instead supplies the owning account;
even when the verified v1 owner names another account (Richard’s private-policy-wins decision). Such changes are reported in `owner_overrides` and stamped as imported legacy provenance, retaining the original owner and verified account evidence. Private records never default to a
different administrator. The importer requires exactly one explicit root account
with Manage to identify the workspace administrator.

Home replacement policies are preserved. Since the probe kernel has no live
membership roster, `members` grants require `--members-file`, one live hosted roster account ID per line. Missing input for an in-scope members policy refuses before target creation. Only the supplied roster is expanded; canonical account bindings are identity evidence, not membership evidence. The report includes the exact `expanded_members` set and `excluded_bound_accounts`. An explicitly empty file supplies an empty roster. This is a frozen roster, not future hosted membership synchronization. Direct account policy grants also get stable principal
bindings. Reconciliation checks visibility for every mapped account against the source replacement policy and original v1 owner bindings, independently of the chosen v2 owner. At exclusive account-only private boundaries, Richard’s private-policy-wins decision supersedes any conflicting legacy owner floor; verification expects only the policy account, and preserves the conflict as override evidence. The sealed
relationship transform service receives temporary Edit grants during relation
conversion. Policy import/grant/restore events are sealed and attributed to the
import host, never to a mapped human owner; normal completion (including link failure) restores all policies.
An interrupted process can leave that service grant until resume restores it;
no human account receives it.

## Runtime packages

For a full-snapshot dry run, use `--all` instead of supplying seeds. It selects
every source record and requires `--members-file`, including on resume. The
existing scope exclusions remain explicit refusals, and the v1 root maps to the
kernel root. Binding targets absent from the snapshot and links with missing
endpoints are counted in the report.

Homes whose ownership requires review are quarantined together with their
placement and policy dependents. Each dependent record is reported for review;
unrelated safe records continue importing. Quarantined records retain their
source placement and identity for a later reviewed import. They receive no
fallback home or owner. An incomplete run still exits unsuccessfully, with its
reconciliation report available; identical resume continues the safe import.
Seed mode also imports unrelated safe records and exits 1 when a selected home requires review.

Fresh imports install and adopt the carrier (`native/v1@1`), standard document
(`native.standard/document@4`), relates-to and claims (`native.coordination/claims@1`)
packages at the target root through governed adoption. Ordinary record writes
use the carrier/document packages; relates-to and `start_work` use their
respective providers. Search uses the built-in kernel index. Bootstrap, run
creation/intent/closure, bodies, facets and generic links also use built-in
kernel lanes and require no further package.
Identical resume verifies the installed packages, selection/log agreement and
active definition pins without appending package-adoption events. Changes to a
selection still pass normal governed dependency preflight.

## State and provenance

`Document/note` uses `native.standard/document@4`; other supported records use
`native/v1@1`. Empty names are omitted. Bodies use the kernel body lane. Current
facets retain the last observation's `as_of` by event sequence, never first-set
`facet_values.created_at`; missing observation evidence requires review. The
archived facet maps to the archive flag; its last observation time, when present, is retained as `archive_observed_at` in provenance. Original creator/editor and current-state timestamps, owner
resolution evidence, original placement and lifecycle are retained as legacy
snapshot provenance, not native creation/edit pins. Notes use optional summary
and lifecycle fields in document@4; neither remains legacy-stamp-only.

Every admitted record has kernel-owned `persistence`, `maturity` and
`last_activity_at`, independent of definition fields. Imports preserve these
values and record them as legacy provenance. Native record writes maintain the
activity clock from their event time, including native claim/release changes
through their validated record subject. Provider receipt retries leave it unchanged.
Callers can update persistence
(`enduring|occurrent`, never null) and maturity (text or null), but cannot supply
an activity timestamp. A populated folder cannot become occurrent. Failed
writes and identical idempotency retries do not touch activity.
`metadata_coverage` counts verified values, including nonempty note summaries.

Non-finite facet numbers retain their original text, observation time and
vocabulary reference, with no numeric projection. `nonfinite_facets` reports
the record/key and reason; an absent original text requires review rather than
inventing one. Kernel admission errors retain diagnostic text with source
content redacted. Dependent review entries name the original blocking home.

Ordinary `get_record` and `query_record` report the same visible logical folder ID as SQL;
hidden folders yield null, including when record ownership permits the child
read. `create_record` accepts these folder IDs, `native:root`, and native kernel home IDs; folder attachments resolve through the same authorized import mapping. Native records in imported homes use the same mapping. Pre-W1 imported
targets require recreation: note selection and immutable snapshot payloads
changed. Additive metadata schema backfill for older native probe files derives
native defaults/activity from their log; it cannot recover omitted v1 metadata.

Ordinary KernelV2 `get_record` and `get_history` expose a `legacy_provenance`
metadata block with `kind: "v1.snapshot_provenance"`, original creator/created_at
and last_editor/updated_at. Creator/editor IDs carry `v1:` prefixes; they are
legacy claims, not authenticated v2 principals. Default text reads label these
as imported snapshot provenance. The metadata remains frozen after native edits;
top-level record clocks and native event actors keep their v2 meaning, including
for write guards. Full legacy payloads, owner evidence and policy details are not
exposed by this block. Record visibility is checked before reading the stamp;
creator/editor attribution is withheld without root-directory visibility, matching
kernel history's actor fence. Non-imported records have no legacy stamp.

Two directed `relates_to` links become one unordered relation assertion with two
sources, keeping original IDs, direction, claimed author/time and note. Author
evidence comes from the current content-owned edge or the governed relationship
creation/source facts; removed earlier edges and migration receipts do not supply
a guessed author. The kernel
provider supplies native assertion attribution. Every other predicate uses the sealed generic-link import lane, preserving the original link ID, verbatim relationship, creation timestamp and note; the lane prefixes the raw legacy actor with `v1:`. Both endpoints must have imported successfully. An existing active triple with another ID is reported for review with both IDs; the importer never substitutes that identity. Admission and provenance conflicts are reported as refusals. `links_by_relationship` counts imported links, generic creations/updates/unchanged retries, generic read verification, skipped endpoints, refusals and review items. Generic links are verified through authorized kernel reads while the sealed transform grant is active. Identical resume retries append no generic link events; note-only changes retain the imported identity and creation provenance. The verify pass reads every imported record, facets and snapshot provenance
through authorized reads and compares fields/title, body, archive, lifecycle,
placement and owner; it also checks account visibility.

`Document/attachment` records use the immutable `native/v1@1` carrier, with
kernel-owned blob metadata and their original `blob_ref` facets. The importer
copies held bytes from the snapshot, verifies SHA-256 and size, and atomically
commits each record and blob reference. Missing, external or corrupt bytes are
refusals; source URLs are never fetched. Legacy handles map to content hashes,
and per-reference filename/MIME/timestamp metadata survives deduplication.
Replay retains the byte substrate and rebuilds handle/reference projections.
Empty imported folders also receive home boundaries for later `attach_text`.

Messages, conversations, annotations/comments and artifacts still lack their
specialized v2 read surfaces. Current-state import does not invent historical
events when source creator/editor evidence is missing. W5 retains the available
source event streams as described below.

Importer retry comparisons use exact serialized payload strings, avoiding a parse/reserialize float conflict. The crate-wide serde_json number parser remains unchanged. Probe facet envelopes parse their numeric token locally with Rust's f64 parser so projection and replay preserve the stored number.

Full imports materialize link-attribution keys once in indexed, in-memory TEMP
storage on the source connection. The snapshot file remains physically read-only.
This avoids scanning the complete content log for each link while preserving
NULL actors, exact identity/time matching and removal ordering.

Instruction bindings use S6's sealed `import_instruction_binding_as` path. All workspace bindings and account bindings for the workspace owner and supplied live member roster add their target records and ancestors to the subset, including disabled bindings. Other bindings import when their targets are selected. A roster is required before target mutation when non-owner account bindings exist, so membership is never inferred from account bindings. The `standing_targets_added` count discloses automatically selected instruction targets.

Original binding ID, scope ID, position, enabled state, creator and creation timestamp are preserved. Account principals are derived exclusively from the binding's `scope_id` using the same account→principal map as owners; a target record's owner never supplies this mapping. Verification re-reads each projected binding and resolves its scope ID through principal auth bindings, checking both correspond to that map. Imported binding scopes do not grant record visibility. Mutable target/position/enabled state uses sealed updates; identical retries append no binding event, while creation-provenance changes refuse.

The report's `instruction_bindings` contains total/selected-target/per-scope counts and created/updated/unchanged/verified/refused counts. `not_yet_imported` retains excluded rows and any row that failed import or verification; selected-target failures also produce refusals or review items. Absent source tables are disclosed. Creator IDs and timestamps are recorded in kernel provenance rather than emitted in the redacted report.

On resume, unchanged root package setup is recognized through verified selection/log agreement, acknowledgments, attributor and active installed definition pins. It does not re-adopt those packages: adoption dependency preflight correctly refuses when the admin cannot inspect private member records, even for an exact retry. Actual selection changes continue through the governed adoption API. This does not give the admin visibility into private instruction targets.

## Test inventory continuity

The KernelV2 registry test
`v1_import::tests::imported_account_callers_resolve_through_kernel_v2_registry_and_bindings_are_reported`
was renamed to
`v1_import::tests::imported_account_callers_resolve_through_kernel_v2_registry_and_bootstrap_is_ready`.
It retains the authenticated caller and account-owned/private visibility checks,
and now verifies imported bindings and ready bootstrap instruction resolution.
The rename is reviewed with the `ci/test-removal-reviewed` PR label and a
`Test inventory change reason:` line identifying the replacement.

## W5: retained full history (offline import only)

Pass `--history` when importing a seed subset, including with `--resume` after
current state was imported. `--all` includes history (`--all --history` is also
accepted). Complete this phase **before v2 becomes live**: every legacy event
and its attributed migration receipt advances the record's sequence-based CAS
revision. The importer uses the sealed host principal; ordinary MCP writes
cannot invoke this seam. History import does not fold v1 mutations over current
state, install historical v2 pins, or change current body/facet/archive/link
projections. Replay validates the import receipt and retains this separation.

The content, relationship, policy and control streams retain original IDs,
types, actor, run key, time and parsed payload in `kernel.legacy_recorded.v1`.
`legacy.source` stores origin, stream, mapped visibility subjects, remaining SQL
metadata (including local `seq` and original `act`), and `row_sha256`: SHA-256
of the extracted source row serialized as a JSON object, including its
verbatim payload text. The parsed payload is stored once; raw SQL rows are never
returned by reads. Headers are not duplicated in source metadata. This retains
payload meaning and detects byte-level changes without retaining escaped payloads
a second time. **Verbatim payload bytes are not retained in v2**: retain the
archived v1 snapshot as the fidelity witness for the row hash and original bytes.
All streams merge by `(act, created_at/occurred_at, stream, seq)`;
missing acts sort as zero. Mixed `created_at` spellings (for example a space
versus `T`, or differing fractional precision) can misorder pre-act-cutover rows
within a second because this tie-breaker compares the original text. This is
retained v1 ordering evidence, not native v2 causality.
Legacy causal status stays `legacy_unknown`.
Duplicate IDs with different envelopes refuse; identical retries are unchanged.
A partially completed phase can resume with the same snapshot and full seed set.
`--all` is the supported full-history route. Expanding seed mode from A to A+B
can change an event's anchor and refuses rather than moving immutable envelopes.
Use a fresh target after changing envelope format or ordering; old W5 trial
history targets cannot resume into this format. Targets imported under earlier
W5 heads must be re-imported and re-verified before cutover; prior trial results
are not qualification for this head.

Content/policy events attach to the imported record, or its mapped home when
there is no record (notably `native:root` → `kernel:root`). Relationship creation
supplies endpoint subjects for its entire relationship stream; the event is
stored once on the first imported endpoint and appears in either endpoint's
history. Control events attach to a referenced imported source/root/artifact/
person, otherwise the kernel root. Relationship events without imported
endpoints also remain on the root. Events for selected tombstones and unsupported current-state kinds remain
retained on the root, counted as `retained_without_imported_subject`. Their
missing visibility subjects withhold them from generic reads; no record is
resurrected. In seed mode, unselected subjects are counted as
`skipped_subject_not_selected`. A full import retains every source envelope.

`history.streams` reports source/created/unchanged/verified/skipped/unmapped counts.
Verification independently compares exact ID sets and counts per stored record
or home, excluding synthetic snapshot provenance and migration receipts.
`records_verified` counts those anchors. A mismatch aborts the import.

KernelV2 `get_history` keeps stable target-local pagination and original v1
IDs/types/times, with `v1:` actors and a `legacy_interpretation` marker. Metadata
is the default; `detail=full` supplies redacted retained v1 payloads when
directory attribution is visible. Source rows and migration bookkeeping never
travel as payloads. Migration receipts are excluded by default; the explicit
`include_import_receipts=true` detail flag includes only receipts whose witnessed
legacy event is visible to the same caller, even when it is outside the page.
Authorization and payload redaction occur in one snapshot, using v1's shared per-key redaction rule.
Identity keys are erased even for root viewers; hidden record references are
nulled and claim keys are erased unless the caller holds the claim. Hidden
history types and acknowledgement events are omitted, including when an
unsupported acknowledgement has a separately imported policy home. Hidden annotation targets
and occurrence artefacts withhold the whole event, including quoted selectors.
Anchored comment history requires View on the anchor target (replies inherit the
root anchor). Without an anchor, root and reply history follow the terminal
`part_of` bearer, as comment capability does. Missing/refused anchors alone do
not erase history; hidden referenced targets still withhold their retained events.
Empty-subject events require root Manage or the owning account; account control
and run events obey the same restriction even when they name a visible record.
Account ownership comes from explicit `account_id` or an account-scoped
`scope_id`, including private instruction bindings on visible source records.
An actor is not ownership proof; unproven control/root rows stay admin-only.
Missing subjects withhold tombstone/unsupported-record evidence. Directory View
alone never authorizes another account's unscoped control history. Without root
View, retained payloads and attribution remain withheld. Canvas deltas and private
agent-run payloads require specialized readers.
`kernel_legacy_subjects(subject_id, seq)` and `kernel_legacy_history` are replayed
projections. Cursor and page bounds are applied in SQL; metadata reads select
headers and disclosure facts without fetching/parsing retained payloads or querying
provenance per row. Hidden/restricted disclosure facts are filtered in SQL before
page bounds, including the corresponding receipt facts, to avoid rescanning
private root controls once per visible-page batch.
Native v2 event payloads remain unavailable through this adapter.

Still missing: KernelV2 `whats_changed`, historical/as-of record reads, v1 body
revision reconstruction, specialized canvas/agent-run replay views and v1
facet-history interpretation. Retaining the immutable evidence does not make
these v1 reducers into v2 reducers. Current-state reads remain authoritative.

History appends commit in batches of at most 256 rows. Every historical row
still has its own host-attributed native receipt, with a complete native causal
frontier; all receipts in a batch precede its legacy rows in one migration act.
The first receipt consumes the current heads. With no intervening writes, each
following receipt's frontier is exactly its predecessor, avoiding repeated
whole-log discovery and ancestry walks. Fresh receipt IDs are checked for
existing incoming references. Historical rows remain `legacy_unknown`, and
original v1 acts remain in retained source metadata. Failed batches roll back;
completed batches remain idempotent on resume.

Import reports include wall-clock `phase_seconds`. Dotted entries are included in
that parent phase, so do not sum them twice. `records.atomic_state_body_facets_blobs`
measures the existing sealed record write, including its body, facets and optional
blob reference; those lanes are not separate import passes. Source facet/blob
reads are timed separately. `comments` combines comment records and anchors;
its dotted subphases measure their source reads and writes. `history` measures retained history import and verification, including the busy-record
read diagnostic when available. Timings are diagnostic and are never recorded
as kernel events or included in receipt identities.

Full-copy performance uses the same sealed per-record transactions and SQLite
durability settings. The SQLite append cursor first checks the indexed incoming
references for a new event ID. With no incoming edge, no ancestor path can reach
that ID; self-parenting is already refused by envelope validation. Referenced IDs,
including unresolved forward references, retain the full recursive cycle check.
The generated causal frontier and recorded event payloads are unchanged.

The source reader stages link add/remove facts in indexed SQLite TEMP tables on
its existing read-only snapshot connection. The source file stays read-only;
these tables disappear with the connection. JSON expression affinity, active
generations, explicit/fallback link IDs, timestamps and nullable authors retain
the direct reader's comparison semantics. Malformed JSON disables this cache and
uses the original reader, preserving its handling of otherwise unreachable facts.

Generic links retain their original sealed import order. Read verification runs
after all links are installed, while the temporary transform grants remain in
place, so a link into a comment is checked against its complete bearer thread.

## Delta resume

`--resume` reconciles current state against the newer read-only snapshot. Keep
using the full seed set, or `--all`. Missing rows are checked against the whole
snapshot: dropping an ID from the seed set never implies deletion. Duplicate
source `link_id`s refuse the run before any target writes, including on resume.
A target-file import lock prevents concurrent resumes from interleaving.
The target records the content/control event frontiers before applying changes and refuses
an older or divergent frontier on later attempts, including after interruption.

Only identities with sealed import lineage are eligible for removals. Missing or
soft-deleted source records become tombstones, retaining their identity,
content and history. The removal event retains source origin/frontier, reason,
source deletion time when known, and available legacy evidence. Snapshot absence
is an import-host observation; it does not invent a v1 deletion author or time.
Ordinary record reads, SQL, search and writes hide tombstones just as v1 does;
the sealed tombstone projection retains the original deletion time when known. Resurrection of a tombstoned identity
requires review. Archive/unarchive remains a separate reversible source state. When an imported
record is edited and then deleted between snapshots, its final present source
state commits atomically with the tombstone. A host-only kernel read verifies
that state; ordinary caller reads still return missing. If the source row is
absent, the tombstone retains the last known state instead of inventing it.

Complete record snapshots replace body, definition fields, metadata, facets,
archive state, owner and placement in one host act. A missing facet is an unset;
a detached attachment loses its reference, while immutable bytes and history
remain retained. Native record edits refuse source replacement for review.
Moving a bearer also moves its existing comment thread atomically; the later
comment pass verifies every comment in its terminal bearer's home.

Generic-link removals use a host-only sealed lane and preserve the original link
identity as an inactive row. D9 changes retract the old imported assertion and
assert its remaining source directions; native assertions on that pair survive.
Each provider receipt remains atomic. An interrupted replacement can temporarily
leave the pair retracted; resume completes it without duplicating an assertion.
Live comment bearers outside the current selection do not cause tombstones;
structural availability is checked against the whole source snapshot. Native
attachment references and comment anchors are not removal candidates.
Missing instruction bindings are disabled with removal evidence, while retargets
use sealed binding updates and the shared account-to-principal mapping. A live
target refused by the current import retains its prior binding and is reported;
only removal or retargeting may disable the prior association. Removal evidence
always uses the content/control frontier shape, including binding removals. A binding
whose source target is deleted is counted as `disabled_target_deleted` once its
sealed disable is verified; subsequent resumes do not repeat an unresolved
binding-target refusal. Missing
comment anchors are removed through the host seam. Missing or tombstoned imported
homes are retained and reported for placement review rather than erased beneath
records; ordinary writes refuse a tombstoned folder's alias or derived home.

Home policy and parent/owner changes use sealed home snapshots. A changed
workspace administrator requires explicit ownership review; replacing entries
alone would retain the old kernel root owner's permission floor. The existing
roster seal remains authoritative: a different supplied member set refuses
before policy changes and reports added/removed account IDs. A later seed-mode
resume may need a roster even if the first subset did not.

Reconciliation commits per act. Serve the target only after its report passes.
`delta` in the JSON report counts applied changes by kind. Identical retries do
not repeat removals. Review/refusal entries identify unsafe reconciliation rather
than silently treating it as success. The real-data evidence stays outside the
repository; only synthetic mutation fixtures are checked in.

History delta resume retains the original anchors of every previously imported
record, including tombstones and records now absent from the source. Durable
import-home mappings are retained for history anchors even after a source home disappears. `--all --history --resume` appends new retained events and verifies existing IDs without
folding historical writes over current state or importing an event twice.
Previously retained events reuse their recorded interpretation metadata and
anchor after their raw source-row digest is checked. The sealed import still
compares the full reconstructed envelope. A changed historical source row refuses
rather than rewriting the retained event or silently accepting different data.

Resume upgrades pre-history targets by creating the retained-history disclosure
tables. If either disclosure table is missing, both projections are rebuilt from
canonical retained envelopes in the same transaction; events are never rewritten.

## Artifact, installation and canvas custody (W7a)

Artifacts now use the ordinary imported record carrier. The sealed
`kernel_app_state` projection separately retains source attestations, input
pins, module grants/releases/dependencies, installation consent/adoption rows,
canvas objects/batches, and their referenced content/control events. Exact
source JSON TEXT remains text; SQLite REAL cells use tagged IEEE-754 bits.
Custody events use reserved aggregates and are excluded from ordinary history
and SQL. They do not change the bearer's revision or expose another account's
installation consent. No MCP tool reads custody directly.

Each capsule records its format, source schema and content/control frontiers,
and missing referenced evidence. Frontiers cannot regress. Missing required
source tables skip the entire custody reconciliation, preserving prior capsules
and their frontiers. Only present empty tables establish deletion. The report
exposes `capture_complete`, missing tables, unavailable bearer counts, bearers
with evidence gaps and the largest serialized capsule size. Historical source
closures may exceed the size of any single artifact body; capture retains them
without truncation.

Capture coverage is not executable closure admission:
`executable_on_kernel_v2` is always false and capsule closure admission remains
`not_evaluated`. Partial selections can retain incomplete dependencies. Missing
evidence, skipped capture or an interrupted multi-act import must never qualify
an app for activation. Subsequent live adapters must validate complete closures
and current user visibility, admit the exact installation/source pins, and fence
source reconciliation before native app or canvas mutations become authoritative.
W7a does not implement app launch, rendering, canvas CAS, subscriptions or coedit.

Historical `alpha_tab.*` and other explicitly account-scoped controls also use
sealed custody aggregates, isolated
by their declared account and source origin (unowned evidence is quarantined
per event). They never advance a public artifact's revision or update time.
No ordinary reader, including the declared account or a root administrator, can
read these forensic streams. Blank or contradictory account declarations are
quarantined per event. Custody markers version this placement; they convey no account/app authority.
Existing pre-isolation history remains replayable, but the importer refuses to
resume such a target, even without `--history`. Such probe targets require a
fresh import: canonical event envelopes are never relocated or rewritten.

## App read projections (W7b)

Explicit v2 preparation rebuilds logical SQL event headers from sealed legacy
envelopes. A scanned legacy-log position includes envelopes without a header;
preparation after an older importer appends events catches up only the missing
headers. An open handle refuses record SQL while that projection lags,
rather than returning incomplete feeds; run preparation to catch up. Missing
disclosure/header tables rebuild from the canonical target
log in bounded pages during preparation. Serving opens never repair schema or
catch up projections. Neither path needs the original snapshot or rewrites
canonical events. Read-only copies must already contain these projections.
Source creation time and native creation time remain separate. Imported event
headers retain source identities while their SQL local cursor is the canonical
kernel position; migration receipts do not become user content events.


W7 native consent activation (probe only): `kernel::app_installs` is a separate
native authority derived from a host-sealed activation receipt. The host proof
binds the exact frozen source head, verified report digest and capsule event
positions; an attempted import head alone is insufficient. H3 identity activation
must precede it. Only frozen adopted Docs 0.8.2/0.9.0, Spaces 0.7.0 and Whiteboard
0.2.0 pins are eligible. Unmapped accounts remain in forensic custody. Other
mapped installs retain their rows with an explicit unsupported verdict.

Activation copies pinned bytes and consent generations into replayable native
state. Later custody is not consulted as current consent. User removal changes
the generation on a private aggregate and does not require artifact visibility.
Offboarding revokes personal consent, even before app activation; rejoin and
repeated activation cannot revive it. Neither transition changes the public
artifact's record version. Current source-import mutation APIs close at hosted
activation; replay still accepts the historical imports.

This is host preparation infrastructure, not a launch adapter. Reusable bundle
delivery, current policy checks, atomic MCP attribution, subscription invalidation
and unchanged-app acceptance remain required. W4 must stop/drain importers and
exclude old processes and write credentials from the promoted serving generation.
Opening-time checks and a renamed database path do not fence older open handles.
No live activation is qualified by the preservation-only real snapshot run.

W7 day-one acceptance also requires the other HQ members to install and adopt
the same frozen Docs/Spaces/Whiteboard versions through v1-equivalent consent,
source acknowledgements, declared-read checks and account/database scope rules.
Preserving the four existing installs is not sufficient. New package versions
and catalogue changes are outside this cutover. The consent-storage foundation
does not yet implement that complete install/preview/adopt flow. Personal staging
through `app_installs::install_as` accepts only a full frozen source pin that the
current admitted account can view. It creates `caller_asserted`, non-executable
consent on that account's private aggregate. Replacement requires a removed
predecessor and its exact generation. Accepted operation keys survive projection
recovery, but retries still require current membership and source visibility.
Accounts excluded from the serving roster at activation retain no executable
imported consent on a later join; they must make a new personal consent.

The declared-data evaluator will implement W6c's `AppDataNeeds` interface rather
than a separate subscription transport. Every evaluation and emit revalidation
must check current installation, consent generation and source authority. The
frozen `native.app.v2` declarations have empty engine needs/effects; unknown named
needs refuse, while client-kit SQL reads use ordinary user authorization.


## W8: catalogue, onboarding and historical coordination state

The probe importer retains all vocabulary/value rows (including custom values,
metadata, aliases, status and terminality), the effective schema rows, onboarding
programmes/sources and each member's obligation/progress fold. These are sealed,
replayable current-state imports with idempotent updates and removal reconciliation.
Canonical row JSON is sealed as text, so projection and retries preserve numeric
values without changing serde_json parsing in the v1 production build.
Catalogue/control state is carried in seed mode too; referenced records still
obey the ordinary subset, owner and policy rules. Raw control envelopes are not
ordinary root-history payloads. Account scopes use the same exact account-id
`auth_binding` mapping as record owners, and the kernel verifies that mapping.

`get_record.lifecycle_interpretation` and SQL
`record_lifecycle_interpretations` use the same interpreter as v1: effective
schema context, active canonical values, one-hop deprecated aliases and governed
terminality. Native writes consult imported governing vocabularies: active kind aliases
canonicalize, open/unknown kinds remain preserved for interoperability, new core
tasks/epics default to `open`, and lifecycle updates validate their vocabulary; legacy unknown values remain evidence and read as
unclassified. SQL also exposes `vocabularies` and `vocabulary_values`.

Bootstrap reports onboarding as `read_only`, with `delivery_enabled=false`.
Completed/declined generations never enter `pending`. Member state is scoped to
its authenticated account, programme sources are not disclosed when hidden, and
no obligation is delivered or mutated. Full programme delivery/editing remains
out of scope; all source rows, including original evidence and reasons, survive.

Approved cutover rule: every imported v1 run/intent/claim is historical evidence.
Original IDs, authors, timestamps and source release/close state are retained;
historical rows are retained and counted as `retained_missing_source` if a later
snapshot prunes them; the sealed seam refuses erasure of coordination evidence.
Reservation includes orphan keys found in claims, member state and retained
legacy events, not just rows present in `agent_runs`. No imported run creates a
native run principal or usable runtime key, and no
imported claim occupies the claims provider. New v2 runs can claim immediately.
`state.claims_held_at_snapshot` counts still-held v1 claims that agents must
re-claim after cutover. `run_intents` follows the v1 successful self-authored
read-log declaration rule and reports whether that optional source exists.

SQL `runs` uses `model_assurance='imported_historical'`. Runs without a source
close expose the import observation boundary as effective `ended_at_ms`; the
original nullable close remains in legacy evidence. `agent_activity_claims`
exposes source release time or that explicit boundary, always `is_current=0`.
`get_record.historical_claims` additionally distinguishes original `released_at`
from `effective_released_at`, `historical=true`, and `occupied=false`. These are
migration closure observations, never invented v1 release/close actions. Native runs keep the existing directory rule. Imported runs/intents require
self or View on the verified imported Person; missing/ambiguous links stay
self-only. Derived account-directory mappings are sealed independently of
seed choice, and claims additionally require bearer visibility. Known imported
`principal_person_id` values are retained. Intent ordering uses original
read-log sequence numbers, so pruning cannot duplicate historical ordinals. Import/runtime run-key collisions refuse.

W8 review corrections: sealed host imports bypass native vocabulary write validation for UUID and legacy-shaped record events alike, retaining retired/unknown/null lifecycle values and original kind aliases as evidence. Runtime validation and lifecycle reads use the immediate logical home as their collection-schema context. For an imported record isolated in its own per-record policy home, that context is the stamped `original_home`, matching public filing placement rather than the policy envelope. Ambiguous owner bindings that lose a visibility grant under the private-policy-wins decision are explicitly included in `owner_overrides` with their complete original verified-account set. A private view-only grant may become ownership under that decision. Creating a principal for a historical account grants no workspace membership or policy access.

Historical claim SQL uses the run-key expression index instead of scanning runs per account. Column-free catalogue reads are admitted only through KernelV2-specific validation entry points, followed by the strict physical-table fence; the shared v1 authorizer retains its staged-population refusal even in probe builds. Lifecycle SQL memoizes by type/kind/raw value and logical home, then bulk-stages the result; get_record and native-event validation still rebuild their caller-scoped interpreter rather than sharing a potentially stale cross-caller cache. Keyless bootstrap checks candidate run keys through indexed historical evidence lookups and rechecks at admission, without enumerating legacy content events.

Authenticated KernelV2 transport callers reject the entire `host:` binding namespace at both stdio startup and ordinary registry resolution. Internal import/transform seams retain their separate low-level host lookup.

Native consent and frozen-source projection recovery runs during explicit v2
preparation. Serving opens verify these projections without rebuilding them.

W7 custody schema upgrades and recovery run during explicit v2 preparation.
Serving opens only verify readiness and never rebuild missing custody.

W7b scan frontiers are gap-free across canonical legacy envelopes, including
those without a SQL header. A newer writer cannot jump over an older writer's
unscanned envelope. Explicit preparation upgrades max-only frontiers by
rescanning canonical envelopes idempotently; serving refuses the old format.
Legacy SQL authors follow v1's self-or-visible-bound-Person disclosure rule,
including author labels for non-root members. Hiding the Person hides its
attribution without hiding otherwise visible record activity.

W7 custody includes exact per-account tab order rows and their control-event
witnesses. Only the authenticated account can read its retained arrangement;
these rows never attach to an artifact's public clock. Source deletion marks
prior bearer custody `source_deleted=true`; live activation must refuse it.
Missing required tables leave prior custody untouched but fail capture and the
cutover gate. Evidence gaps and unavailable bearers likewise refuse cutover.

Every physical v1 table must have a literal disposition in
`src/v1_import/table_coverage.rs`. Unknown tables refuse before target writes.
The report distinguishes consumed tables, explicitly discarded tables, and
unclassified tables; consuming a table is not a claim of complete live support.
The discard list includes derived caches and unsupported domain state; those
rows are intentionally not activated, and their source snapshot must be retained.
SQLite BLOB cells in app custody still abort the whole import; they are not
silently converted or skipped. Sealed import refusals retain their error reason.

Source reconciliation closes permanently at the first hosted-membership event
(or native app activation). The importer itself writes source membership facts,
not that serving roster: W6 message/notification, W8 catalogue/control, workspace
metadata and app custody imports all precede serving admission. Import-policy
facts likewise precede the first hosted roster. Notification history is folded
inside the already-fenced message import; historical projectors remain replayable.
The source-import opening gate uses the covering partial index
`idx_kernel_import_closed`, installed at creation/explicit preparation, avoiding
a full canonical-log scan per imported mutation. Older targets require explicit
preparation; a low-level gate call before that index exists would scan the log.
W4 must still stop/drain old importers and exclude their write access to the
serving generation.

Frozen package declarations use canonical JSON for shared pin comparison while
preserving each account's original consent text. Offboarding advances native
install generations to its cleanup event, alongside status and revocation epoch.
Source-deleted custody never creates an executable frozen app source.

Probe-only W7 hosted review operates on native frozen-source/install projections,
never activates a custody capsule at request time. Each admitted HQ account can
stage an exact frozen pin independently; `caller_asserted` staging grants no
execution. Full management lists additionally expose `frozen_sources` qualified
by the caller's current source View. Preview and adoption require a configured trusted origin and H2's verified
same-origin cookie ingress, with separate account/full-pin attestations. Adoption
spends a bounded server-held receipt exactly once after current membership,
source liveness/View, predecessor and revocation checks, and records a private
user-authored `shell_adopt.v1` outcome. Durable keyed retries recheck authority;
server restart or an uncertain uncommitted outcome requires a new preview.

Native review entries advertise `launch_binding.delivery="reusable.v1"`, including
pending entries. The existing shell uses its reusable validator for both sample
and installed frames. A signed preview payload (version 2) binds the original
install generation and receipt ID, with that receipt's exact expiry; installed
payload version 1 is unchanged. Every preview GET rechecks the issuing catalogue
session, native account admission, source View/runtime, generation, revocation
and unspent receipt before a transformed-body cache hit. Missing or consumed
preview evidence never falls back to installed-app admission or one-use tickets.
Cold native bundle reads open only already-marked, prepared primary files with
physical read-only pools; they perform no preparation or identity reconciliation
writes. Standby v2 serving remains unavailable.

This increment supplies install/list/inspect/prepare/preview/adopt/remove, not
app-call admission, mutation attribution, declared-data evaluation, rendering or
canvas execution. Unsupported management actions refuse explicitly. Native app
launch and those adapters follow separately; this is not cutover readiness.


## Native deletion after cutover

`delete_record` requires live kernel Manage and a nonblank reason. It appends a
native soft tombstone: body, facets, links, children, comments and attachment
references remain physically retained. Ordinary children keep their own authority;
comments and attachments become unreadable when their terminal bearer is deleted.
Further writes and ordinary history reads refuse through the same tombstone gate.
Registered personas and active instruction sources cannot be deleted.
Message deletion also retires effective mentions and withdraws its live notification
candidates in the same projection transaction.

The importer retains the two v1 derivation deletion predicates as sealed
`record_deletion_guards` state (active body binding and active artifact role).
It does not activate the v1 derivation runtime. Unknown source tables remain null;
older imports without these facts receive an unavailable-guard refusal rather
than assuming a record is unbound. Refresh the source evidence before activation.
Identical imports append no guard event, and replay preserves the guard facts.
