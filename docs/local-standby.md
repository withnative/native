# Full-owner local standby contract

This document fixes the Milestone 1 dogfood contract for a full Native owner
replica on one trusted laptop. It is a read-continuity release: hosted Native
remains the canonical authority, and the local process cannot author canonical
state or claim that offline writes are supported.

This is the human-readable contract boundary for the first implementation
slices. The snapshot producer, closed provenance schema, offline
accept/promote kernel, startup activation/recovery path, and refresh controller
are implemented; full status disclosure, packaging, and qualification remain
separate slices.

## Release-pinned acquisition

The supported laptop path is the `@withnative/standby` npm package at an
exact version. Its platform-specific optional dependency contains a prebuilt
`mcp-stdio`, plus a `native.standby-artifact.v1` manifest with the full
`NATIVE_CE_GIT_SHA`, engine schema version, frozen DDL fingerprint, and binary
SHA-256. The package verifies that manifest and checksum before copying the
binary into an immutable versioned generation under
`~/.local/share/native-local` (or `NATIVE_STANDBY_HOME`). A clean laptop does
not compile the repository.

```sh
npx --package @withnative/standby@0.1.0 native-standby install
npx --package @withnative/standby@0.1.0 native-standby configure \
  --replica-root "$HOME/.local/share/native-local" \
  --hosted-route ROUTE_DATABASE_ID \
  --origin-database-id ndb_DATABASE_ID \
  --mcp-config "$HOME/.config/mcp/config.json"
npx --package @withnative/standby@0.1.0 native-standby verify --json
```

The generated `native-local` entry launches the stable absolute path with
`--standby` and the strict standby configuration. It is independent of npm,
the registry, and hosted GHCR after installation; the existing hosted `native`
entry is preserved. `native-standby update` is idempotent and refuses to
replace a release version with different bytes. `native-standby rollback`
switches the stable launcher to the prior checksum-verified generation without
removing or rewriting `accepted/`, `device/`, or `refresh/`.

## First-release choices

- Agents use an explicit `native-local` MCP configuration alongside the
  existing hosted `native` configuration. Transparent routing is optional
  later work; an outage must not silently change authority beneath an agent.
- While the laptop is awake and online and the authenticated snapshot endpoint
  is healthy, refresh runs every **2 minutes** and is also attempted immediately
  on startup, wake, and network recovery. A snapshot older than **5 minutes** is
  beyond the dogfood recovery-point objective (RPO). Reads remain available
  beyond RPO, but every status surface must say so plainly.
- Retention keeps the current generation and, once accumulated, up to two prior
  verified generations. A first successful install therefore reports only its
  current generation. Staging, corrupt, incompatible, or partially downloaded
  material does not count as retained.
- The supported schema policy is exact compatibility between the released
  standby binary and a promoted snapshot. An incompatible snapshot never
  leaves staging and the last compatible generation remains current. Failed
  candidate bytes are deleted after bounded diagnosis by default; only
  non-secret failure metadata is retained. Milestone 1 does not migrate a
  promoted generation in place or silently migrate a downloaded copy. A
  compatible pinned binary or a separately governed recovery procedure is
  required.
- The first release supports the dogfood laptop's Linux x86_64 platform through
  a release-pinned, checksummed artifact. A checkout build is diagnostic
  evidence, not the supported installation path. That boundary is enforced by
  the build stamp rather than by policy: the runtime hashes its own executable
  and requires a 40-character lowercase commit SHA as the consumer identity the
  manifest pins, and `build.rs` deliberately stamps `dev` for local builds. **A
  standby artifact must therefore be built with `NATIVE_CE_GIT_SHA` set to the
  full commit SHA**, or it starts in status-only mode and refuses every
  snapshot-backed read. The Dockerfile already passes it; a packaging path that
  does not would produce a binary that installs cleanly and then serves nothing.

## Trust and local custody boundary

The owner explicitly authorizes a complete workspace copy on one Linux x86_64
laptop they control. Mutable replica directories are owner-only (`0700`) and
files are owner-only (`0600`); immutable generation directories and files are
tightened to `0500` and `0400`. Full-disk encryption is a supported-use prerequisite,
attested by the owner rather than verified by Native; ordinary laptop account
hygiene is also the owner's responsibility. Native must not turn either into
claims about encryption, confidentiality, revocation, or remote erasure.
Losing hosted authorization cannot erase plaintext already accepted onto the
laptop.

Snapshot credentials are used only against the authenticated hosted endpoint.
They are never written into manifests, status, logs, refresh failures, or MCP
responses. A refresh failure may expose a bounded class and safe explanation,
not a bearer token or provider response body.

## Accepted state and future device state

The directory model is fixed before offline writes exist:

```text
replica root/
  accepted/
    staging/                       # private accept/promote workspaces
    generations/
      .publishing-*/               # non-authoritative owned verification copy
      <immutable generation>/
        snapshot.db
        manifest.json
    leases/                        # cooperative active-generation locks
    current.json                 # atomically replaced pointer
    startup-state.json           # durable fallback/recovery reason, when any
    promotion.lock               # serializes baseline proof + publication
  device/                        # reserved, never generation-owned or pruned
  refresh/
    state.json                   # durable attempts and non-secret status
```

A download enters a unique staging path. Before publication it must verify the
manifest format, exact byte size and SHA-256, SQLite integrity, portable
`origin_database_id`, hosted route database ID, exact consumer artifact and
engine schema compatibility, and canonical frontier evidence. Publication
makes the immutable generation durable, then atomically replaces
`current.json`. Interruption leaves either the old or new verified generation
current. Ordinary refusal removes its `.publishing-*` workspace; a crash may
leave one behind, but it is never authoritative or addressable through
`current.json`. Refresh and retention may replace only `accepted/`; they never
remove or rewrite `device/`.

Every process start reads a strict external standby configuration which binds
an absolute replica root to the expected hosted route and portable origin. It
hashes the executable bytes through `/proc/self/exe`, then re-verifies current
against that observed installed identity before serving data. If current fails,
the runtime tries retained generations in deterministic authority-capture order
and atomically selects the newest compatible verified prior. A fully durable
successor left between generation and pointer fsync transitions is completed
only after the same rollback and deep-successor proof. If no retained generation
passes, the MCP process enters **status-only** mode: bootstrap and standby status
remain available, but no snapshot-backed read is advertised or dispatched.
Startup does not repair, migrate, or delete the failed generations.

The serving process holds a shared per-generation lease for its lifetime.
Retention takes an exclusive nonblocking lease before removing a known-good
older generation, so a concurrently serving process is never deprived of the
pathname from which its pool may open another connection. Retention may
temporarily exceed three generations while such a lease is active and converges
to current plus two prior generations on a later startup or an explicit
post-refresh retention pass. Interrupted `.pruning-*` workspaces are finished
on the next pass. A fallback/recovery reason is durably recorded before the
recovered pointer is published so the later status slice can disclose it. The
record applies only while its generation still matches `current.json`; a later
successful promotion makes the older marker historical.

The startup configuration is strict JSON and contains no credential:

```json
{
  "replica_root": "/absolute/path/to/native-local",
  "hosted_route_database_id": "the-hosted-route-id",
  "origin_database_id": "ndb_..."
}
```

Start it with `mcp-stdio --standby /path/to/standby.json`, or set
`NATIVE_CE_STANDBY_CONFIG` to that file and pass `--standby`. Raw database
paths are not a standby startup mode; only the generation selected through the
bound config can be served.

## Refresh lifecycle

Refresh is part of the exact release-pinned `mcp-stdio` artifact rather than a
second downloader with an independently drifting compatibility identity. When
refresh is configured, that artifact starts one bounded refresh attempt in the
background at startup. Generation selection never waits on the hosted network:
an existing usable generation is served immediately, while an empty store
enters honest status-only mode until a later process start can activate the
newly accepted generation.

After startup, the same process runs the refresh controller in the background
for as long as its stdio lifetime remains alive. It requests a refresh every
two minutes. The interval uses delayed-tick behaviour: suspension does not
accumulate a burst of missed work, and an overdue tick prompts one attempt
after wake. A wall-clock/monotonic-clock gap detects resume and queues a wake
attempt. After a network-class failure, a bounded ten-second recovery probe
supplements the ordinary cadence until connectivity succeeds; authentication
failures remain on cadence or manual retry. Packaging and service
lifetime are a separate Milestone 1 slice: until that slice keeps the MCP
process alive reliably, this in-process schedule alone is not a claim that a
closed client maintains the RPO.

Only one refresh attempt may run at a time. Startup, cadence, wake, manual, and
future post-admission requests use the same controller and installation path.
Concurrent requests coalesce into at most one pending follow-up instead of
racing downloads, promotion, or retention. Transient transport work has
bounded retries, per-call timeouts, and a bounded whole attempt;
authentication, protocol, verification,
compatibility, rollback, and local-custody failures fail the attempt without
replacing current. The next cadence or an explicit request may try again.

A manual refresh is an explicit mode of the same release-pinned artifact, not
a writable operation on the standby MCP surface and not a second installer.
It observes the same single-controller/coalescing boundary and never bypasses
manifest or successor verification. Run it with
`mcp-stdio --standby-refresh /path/to/standby.json /path/to/refresh.json`.

Refresh transport configuration is a separate strict, versioned, non-secret
configuration bound to the same replica root, hosted route, and portable
origin as standby startup. Hosted credentials come from a separate owner-only
credential file; they do not appear in either standby configuration, refresh
state, process arguments, logs, or status. The exact configuration flag and
environment-variable name for background refresh is
`NATIVE_CE_STANDBY_REFRESH_CONFIG`; it complements, and does not replace, the
ordinary standby configuration. Unknown fields fail closed without affecting
an already accepted generation. The hosted route and portable origin remain
authoritative in the referenced standby configuration rather than being
duplicated in refresh configuration.

The refresh configuration has this strict non-secret shape:

```json
{
  "contract": "native.standby-refresh-config.v1",
  "version": 1,
  "hosted_origin": "https://plugin.withnative.ai",
  "credential_file": "/absolute/owner-only/path/to/native-local.token"
}
```

`hosted_origin` is an exact HTTPS origin without credentials, path, query, or
fragment; HTTP is accepted only for loopback qualification. The controller
constructs the scoped `/mcp/<hosted route database ID>` endpoint itself.

Every full snapshot acquisition, including delta fallback, uses the binary
route and allows up to 30 minutes for hosted capture,
filtering, verification and hashing. The local refresh attempt allows 45
minutes including transfer and local verification. Individual HTTP requests
remain bounded to 10 seconds, range retries remain bounded, and capture
single-flight, retained-export limits and owner checks still apply. These are
acquisition budgets, not measured HQ timings or a five-minute freshness promise.
An expired handle does not interrupt SQLite capture; its resource lease lasts
until capture and cleanup finish. Do not repeatedly start new full captures
when seeding fails.

An initial capture may outlast an OAuth access token. Binary polling, range
requests, retries and cancellation re-read the guarded credential file, so a
separate owner credential controller can atomically renew it without restarting
the capture. The runtime does not itself hold an OAuth refresh grant.

A long-running host should use a separate owner-authorized credential controller
with its own refresh grant. Do not share a rotating OAuth grant with an active
MCP client. Renewals should be serialized, private and atomically published;
revoked grants require owner sign-in again. Authentication renewal must not
capture snapshots or change canonical workspace data.

Enable recurring snapshot refresh only after seeding and measuring subsequent
refresh cost. If delta compatibility is refused, a refresh may fall back to
another full capture; a two-minute timer must not repeatedly impose unmeasured
database-sized capture work on production.

`refresh/state.json` is the durable, atomically replaced non-secret status
projection. It distinguishes the active and last completed attempt from the
last successful refresh, records attempt and success times, the successful
generation and snapshot capture time/frontier, a bounded safe failure class,
consecutive failures, and whether coalesced work remains pending. Candidate
generation identity and manifest timing/frontier are persisted before
promotion so a restart can reconcile the pointer publication boundary. On
restart, an interrupted attempt is reconciled against the accepted current
pointer or only that attempt's incomplete staging files are discarded. A
missing state file means no refresh has yet been recorded; malformed or newer
state degrades refresh diagnostics and must not make a usable accepted
generation unreadable. Snapshot age and the RPO are derived from the current
manifest's conservative `captured_at`, never from a successful HTTP response
or filesystem modification time.

A successful background refresh durably promotes and retains generations for
the next process start, but does not hot-swap the SQLite database beneath the
running MCP process. That process keeps its startup-selected generation and
lease until exit. Status must distinguish the generation currently being
served from a newer accepted pointer when they differ.

Refresh changes filesystem control state and immutable accepted generations;
it performs no database migration. Existing accepted bytes are never migrated
or rewritten, including when the installed artifact changes. Introducing the
refresh directory and its versioned state requires no Native SQLite schema
migration.

Promoted database bytes are immutable. The runtime opens its canonical SQLite
connections with SQLite's physical read-only flag, performs no migrations or
startup repair, and suppresses read-interaction capture and run/intent
persistence. Filesystem permissions are defence in depth, not the enforcement
boundary.

## Snapshot and frontier evidence

The hosted source is owner-authorized and transactionally captures one complete
SQLite image. The manifest is derived from the completed exported image, not
sampled independently from the live database, and contains:

- hosted route database ID and the portable `origin_database_id` embedded in
  the snapshot; these are different identity domains and both are pinned;
- conservative capture time, engine/schema identity, and the structurally
  validated released-consumer declaration bound for later installer proof;
- a closed, versioned canonical-frontier value whose permitted coordinate
  names and comparison rules are defined by the provenance implementation;
- exact byte size and lowercase SHA-256.

The frontier schema and its fail-closed upgrade rules are fixed before
promotion; an open string-to-integer map is not a ratified contract. A
generation may replace current only when the closed
comparison says it does not regress canonical state. Unknown frontier versions,
unknown coordinates, missing provenance, an incompatible pinned consumer, or a
manifest/byte mismatch fail closed and preserve current.

The implemented machine contracts are
`native.standby-snapshot-manifest.v1`, `native.canonical-frontier.v1`, and
`native.standby-consumer.v1`; each also carries numeric `version: 1` and rejects
unknown fields. Frontier v1 carries ten sequenced canonical logs plus the
authorization epoch and storage-portability-policy revision. A scalar precheck
passes only when every coordinate is greater than or equal to current. Equal
vectors with different bytes still enter the deep database proof because an
unsequenced provenance stream may advance without moving a scalar. This vector
is deliberately not claimed as a complete promotion proof: promotion must also
prove prefix inclusion for read-visible append-only domains without a global
sequence, validate governed projections, and keep unfenced mutable state equal
unless a ratified authority proves its successor relationship. Operational
read-log, job, and receiver-local relationship-quarantine bookkeeping is
disposable and is never replayed locally. Agent-run state is a deterministic
control-log projection and is folded locally with the rest of that domain. The
in-place storage-portability policy is conservatively frozen byte-for-byte
across promotion until it gains a ratified history or successor proof;
semantic validation alone cannot prove
that a higher revision belongs to the same lineage.

Canonical state is not synonymous with sequenced state. It consists of the ten
sequenced act-stamped logs; the three non-sequenced act-stamped logs
`provenance_attestation_validity_events`, `external_observations`, and
`awareness_command_intents`; immutable companions selected by joins from those mutations; and
small canonical state that requires explicit carry, comparison, or
seed-equality rules in the delta protocol. Everything else is either an
incremental fold of that authority or receiver-local/operational state. The
engine-table classification beside the schema contract is exhaustive. Its DDL
parser rejects table-creating statements it cannot understand, and the
inventory fails closed when fresh-schema DDL adds a table without a carriage,
pin, fold, or exclusion decision. Projection inventories are cross-checked
against the fold classification so a known replay table cannot be labelled
disposable.

Steady-state refresh now probes the authenticated authority act head first. An
equal replicated head is a one-probe no-op. An advance fetches one bounded,
authenticated whole-act delta, clones the accepted immutable generation into
private staging, and applies the canonical events through the same per-event
projectors and DDL triggers used by the authority. The candidate is admitted
through the ordinary deep generation verifier and becomes visible only when
the durable current pointer is switched. The prior generation remains served
and restart-safe until that promotion completes.

The no-op path does not hash or deep-verify the snapshot bytes. It checks the
immutable generation/pointer identity, reads the local act head, and performs
the remote head probe; deep verification is deferred until immediately before
an advancing generation is cloned. The head probe itself still scans the
act-stamped validity log for its maximum act and serializes the governed
storage-policy subtree. Those authority-side costs remain bounded correctness
work to profile and optimise separately; they are not database-file-size work.

SQLite `application_id` carries a database-local source-history provenance
marker. Fresh native databases and revision-5 imports are marked exhaustive;
compatibility imports retain their original revision. Unknown or pre-revision-5
history refuses act-head/delta service and uses whole-snapshot refresh, so a
compatibility upgrader cannot relabel omitted historical events as exhaustive.

An identity change, incompatible or unrepresentable cut, or a delta above the
transport ceiling takes the existing whole-snapshot path. A failed fallback
leaves the current pointer unchanged. Full replay stays bootstrap, repair, and
verification machinery rather than the steady-state refresh algorithm. There
are no global-rebuild derived tables today; that bucket remains explicit and
empty so a future global dependency cannot silently acquire an incremental
claim. Generation provenance durably records the accepted act head and whether
the file was materialised by snapshot or delta, and `standby_status` projects
both across restart.

This delta classification is narrower than canonical interchange and the
legacy whole-file successor proof. Interchange may carry operational sections
for a complete logical migration even when a local standby delta discards
them. Likewise, the legacy snapshot gate may require a candidate file to
preserve operational append-only rows (including migration drills and local
attestation-authority evidence) without making those rows part of the new
delta protocol.

Ordinary `export_snapshot` calls remain generic and carry no manifest. On the
first call only, a hosted owner may supply `standby_consumer` with the exact
Linux x86-64 full source SHA, artifact SHA-256, engine schema, and frozen DDL
digest expected by the installer. The producer structurally validates and
binds that declaration to every page and the final retry cache; this is not
proof of installed bytes. The installer must observe the installed
executable's build identity and hash those exact bytes, then validate all five
fields through the shared compatibility seam. Local exports reject
`standby_consumer` and never claim hosted provenance.

Manifest freshness uses `captured_at`, sampled immediately before `VACUUM
INTO`, as the conservative RPO boundary. `snapshot_completed_at` reports later
SQLite snapshot verification completion and must not make an old capture
appear fresher.

## Milestone 1 MCP surface

The hosted snapshot producer, local offline accept/promote kernel, and local
startup activation path are implemented. The kernel verifies staged bytes and
manifest evidence, performs rollback and projection checks, publishes immutable
generations, and switches its durable current pointer atomically. `mcp-stdio`
resolves that pointer through a strict standby runtime config, revalidates the
selected generation, falls back safely, holds an active-generation lease, and
prunes only unleased known-good generations. With no usable generation it runs
a database-less MCP exposing only bootstrap and `standby_status`; every exact
snapshot-backed call fails with `STANDBY_STATUS_ONLY`. Configured network
refresh acquires and promotes newer generations without making the serving
database writable. Bootstrap, `engine_info`, and the dedicated
`standby_status` read expose the active snapshot's provenance and freshness,
the separately accepted generation, and live refresh diagnostics. Packaging
and integrated qualification remain future work; this is not yet a complete
Milestone 1 standby.

The standby serves only observational capabilities needed to recover context:

- bootstrap, engine/system information, guidance, and the dedicated live
  `standby_status` provenance/freshness read;
- search, structured queries, scans, and read-only SQL;
- record, history, change, structure, relationship, facet, citation,
  attribution, attachment, and schema reads;
- artifact, collection, suggestion-review, and version-diff rendering or
  verification that does not mutate accepted state.

Mixed tools expose only their read operations. Mutation-only tools and executor
write operations are omitted from discovery where the protocol permits. An
exact-name call, a mixed-tool write action, an executor bypass, or any future
unclassified operation is rejected before its handler with the stable code
`STANDBY_READ_ONLY`. The physically read-only SQLite connection is the final
backstop. This includes bookkeeping that is normally useful: local reads do not
append interaction logs, mint persistent runs, persist intent, reconcile
defaults, export another local snapshot, or wake write-oriented realtime
machinery.

No response may describe an empty future outbox as write capability. Later
milestones add a separate device outbox and accepted-plus-pending projection;
they do not relax direct writes to a promoted accepted generation.

## Honest status and independent failures

Bootstrap and the status read share the versioned status shape. They report
standby or status-only mode, read-only/write capability, hosted canonical
authority, hosted route database ID, portable `origin_database_id`, the
process-leased serving generation separately from the dynamically accepted
generation, snapshot and promotion times, frontier,
consumer artifact and engine/schema compatibility, last attempted and
successful refreshes, refresh activity, age, target cadence/RPO, explicit
fresh/stale and beyond-RPO state, retained generations, startup fallback, and
the last safe refresh failure.

Every successful snapshot-backed read also carries a compact standby context.
It identifies the hosted canonical authority, the leased serving generation,
and freshness derived from that generation's conservative `captured_at`. The
compact context is explicitly freshness-scoped; `standby_status` is the full
live provenance, accepted-generation, and refresh-health read.

In status-only mode there is no current generation, snapshot, frontier, age,
or fresh/stale claim: freshness is `unavailable`. Status carries a stable
status-only reason plus bounded retained-candidate and failure diagnostics.
Bootstrap returns only local standby orientation and diagnostics in this mode;
it does not attempt snapshot-backed workspace guidance.

Failure boundaries are independent:

- Hosted MCP failure does not stop reads from current.
- Snapshot endpoint, authentication, or network failure records a refresh
  failure and preserves current.
- Verification, identity, schema, frontier, or promotion failure preserves
  current and never reports the staged candidate as healthy.
- A local MCP restart re-verifies current, falls back newest-first to a
  compatible retained generation, or serves status-only if none verifies. A
  refresh process restart resumes safely from durable state or discards only
  its own incomplete staging path.
- Restoring hosted service advances accepted state only through another
  verified refresh. Milestone 1 performs no reverse upload or SQLite file
  synchronization.

## Recovering a downloaded snapshot offline

If a refresh finishes downloading but its overall time budget expires during
admission, retain the original producer manifest and snapshot in a private
directory before staging cleanup. A retained download is not an admitted
generation and must not be served directly.

The maintainer example can admit those same bytes without a hosted request:

```bash
cargo run --example standby_admit --features dev-tools -- \
  /absolute/runtime.json /absolute/installed/mcp-stdio \
  /absolute/preserved/snapshot.db /absolute/preserved/manifest.json
```

The example observes the installed executable's `--standby-identity`, hashes
its actual bytes before and after that observation, and requires its engine
schema and DDL to match the admission helper. It passes that evidence to
`GenerationStore::install_staged`: route, origin, consumer, snapshot identity,
full conformance, awareness, continuity, and atomic publication checks remain
in force. It never rewrites the manifest or marks history qualified. An
identity mismatch is a refusal, not permission to relabel the download.

Offline admission writes aggregate verification progress to stderr while retaining
its final JSON receipt on stdout. Named phases distinguish the candidate,
predecessor, snapshot identity/state/integrity checks, observational conformance,
awareness replay, and successor fence. The standby consumer also writes these
safe tracing events to stderr for retained startup generations. Its final startup
verification receipt reports `serving=false` when no generation can serve. Each
check records elapsed milliseconds in report order. A start identifies executing work; a finish records `ok=true` or
`ok=false` for that check or phase only. It does not establish admission or
serving readiness. Only the complete successful operation does so; cancellation
leaves started work without a completion receipt. Diagnostics contain names,
durations and outcomes, never database rows or raw error contents.

Full history replay can outlast transfer. `TMPDIR` may be set to a private,
adequately sized memory-backed directory for disposable replay databases;
accepted snapshots and durable publication remain in the configured store.
This changes scratch storage only and does not remove checks. Measure admission
and fresh MCP startup before activating clients or choosing refresh cadence.

## Acquiring a snapshot before offline admission

For large workspaces, a maintainer can explicitly split one full download from
admission. This avoids spending the network attempt's 45-minute budget on full
history replay. It does not shorten replay or qualify history for delta refresh.

```bash
cargo run --example standby_admit --features dev-tools -- \
  --acquire-only /absolute/runtime.json /absolute/installed/mcp-stdio \
  /absolute/refresh.json
```

This mode observes the actual installed consumer, obtains an authenticated
producer-bound binary snapshot, and retains the existing transfer range,
manifest, route/origin/consumer binding, digest and credential-rotation checks.
It refuses an active refresh
daemon or attempt before starting a capture. The result has `acquired: true`
and `admitted: false`, with private snapshot and manifest paths under staging.
The canonical producer fields and downloaded snapshot bytes are preserved;
no current pointer, refresh-success state, admission or retention pass is run.
Failures clean up the attempt's owned files; successful files remain for the
separate offline admission command above. These acquisition files are excluded
from normal interrupted-refresh cleanup; remove them after use. A process crash
can also leave acquisition files behind, so operators must account for their
disk space. Producer cancellation is best-effort on timeout or process exit;
the producer expiry bound remains the backstop. Do not assume an immediate
server-side cancellation or blindly start another capture.

Run the default offline command with those returned paths, keeping the existing
verified reader running. Complete kernel admission remains mandatory before
publication. Admission atomically updates the current pointer; an already warm
reader keeps its leased old generation until a separately verified replacement
is ready. Neither acquisition nor admission automatically replaces that process
or enables a refresh timer. Measure download, admission and replacement startup
before choosing any sustainable cadence. Refused delta authority still requires
an independently justified history qualification route; this command does not
stamp provenance or certify unknown history.

## External scheduled FULL refresh

`scripts/native-local-refresh.py` provides the narrowed full-copy scheduling
path. It invokes an **already installed, compatible** `standby_admit` helper:
one authenticated `--acquire-only <runtime> <consumer> <refresh>` call, then
offline `<runtime> <consumer> <snapshot> <manifest>` admission. Every existing
FULL acceptance check remains mandatory. This path does not probe act heads,
enable delta refresh, qualify history, rewrite manifests, or read credentials.
The existing refresh config names the guarded credential file; do not put a
token in controller config, argv, or environment.

Use a private mode 0700 config directory and mode 0600 JSON files. Paths must
be absolute without symlinks. Example controller config (paths are illustrative):

```json
{
  "admit_executable": "/private/installed/standby_admit",
  "runtime_config": "/private/standby/runtime.json",
  "consumer": "/private/installed/mcp-stdio",
  "refresh_config": "/private/standby/refresh.json",
  "daemon_path": "/private/source/scripts/native-local-daemon.py",
  "activation_socket": "/private/run/control.sock",
  "cadence_seconds": 21600
}
```

Run `python3 scripts/native-local-refresh.py once --config /private/standby/controller.json`
for one due attempt, or use `serve` for an asynchronous scheduling loop. `once`
honours cadence; it has no force/retry option. The first invocation is due
immediately; subsequent attempts wait **six hours after completion**, including
failures, with no catch-up captures on wake or network recovery. Cadence is
configurable. This conservative policy supersedes the earlier two-minute target
for this external full-copy path; it is not a measured hosted-load or RPO claim.
Hosted capture cost and deployed acceptance measurement remain separate work.

A nonblocking cross-process `flock` at
`<replica_root>/refresh/scheduled-controller.lock` covers acquisition, FULL
admission, activation, status and cleanup. Children inherit the lock so a
surviving phase continues to exclude another controller. Use one controller
config/status path per replica: the lock binds that path and refuses another
status history. The existing helper separately refuses competing built-in
acquisition/refresh attempts. Do not run a built-in refresh daemon alongside
this controller. Helper wrappers must retain inherited descriptors and remain
in their process group; detaching work breaks that lifetime contract.

Default phase deadlines are 46 minutes for acquisition (the helper retains its
own 45-minute network budget), two hours for offline admission, and three hours
for activation. Optional `acquire_timeout_seconds`, `admit_timeout_seconds` and
`activate_timeout_seconds` override them. Timeout or cancellation kills the
owned phase process group before releasing the lock and starts the same cooldown.
Remote producer cancellation remains best-effort, with expiry as the backstop;
there is no immediate retry. If a prior status is still `running` after its
lock becomes free, the controller records `interrupted` and waits a fresh
cooldown instead of replaying any phase. A crash may leave private acquisition
files; inspect and remove only that attempt's owned `acquire-*` files offline.
Normal completion/refusal removes the validated acquired pair. This is bounded
operational recovery, not a restart-proof or live acceptance qualification.

### Candidate-ready / relay activation seam

Admission publishes the kernel's accepted pointer. A warm reader still leases
its old generation. The controller therefore invokes a separate command,
without a shell, after a successful admission result:

```sh
python3 /private/source/scripts/native-local-daemon.py activate \
  --socket /private/run/control.sock --expected-generation GENERATION_ID
```

The controller awaits completion asynchronously while the relay continues old
reads. The activation implementation must start the configured confined official
consumer, wait for actual readiness at the expected generation, check actual
read-only refusal, swap under the relay's request lock, and drain old exchanges
before closing the old reader. It must preserve the old reader on refusal.
Success is exit zero with one bounded JSON object on stdout:
`{"activated":true,"serving_generation_id":"<expected 64-character generation ID>"}`.
Only that acknowledgement makes controller state `succeeded`; accepted-pointer
publication alone never establishes serving readiness. On activation failure,
the newer generation may already be accepted, but the old reader remains the
serving generation. The controller neither rolls that pointer back nor stops
the old relay. A lost acknowledgement after a switch is conservatively a
controller failure; actual serving freshness still comes from the kernel.
Relay/service wiring is a separate delivery slice; this controller adds no
service unit, deployment, or automatic installation.

### Lightweight controller status

Default status is `refresh-status.json` beside controller config; optional
`status_file` selects another private absolute path. It is atomically replaced
mode 0600 and is independent of kernel refresh state and serving freshness.
The relay may expose its whitelisted fields alongside kernel provenance:

| Field | Meaning |
| --- | --- |
| `contract` | `native.local-refresh-status.v1` |
| `state` | `running`, `failed`, or `succeeded` |
| `phase`, `completed_phase` | Current/last attempted phase and last completed phase (`acquire`, `admit`, `activate`); completion may be null |
| `last_attempt_at`, `finished_at` | UTC attempt-start and completion timestamps; completion is null while running |
| `last_failed_attempt_at` | Start of latest failed attempt, retained after later success |
| `last_failure_phase`, `last_failure_error_code` | Retained failure phase and fixed safe controller code; no raw child errors |
| `last_successful_attempt_at` | Start of latest fully activated attempt, initially null |
| `cadence_seconds`, `next_due_at` | Configured cooldown and next eligible UTC time; next due is null during work |
| `durations_seconds` | Measured subprocess elapsed times by phase, including failures, plus total elapsed time |
| `download_bytes` | Acquired snapshot file size from stat, initially null; not inferred from helper output |
| `generation_id` | Admitted generation, initially null; does not imply that it is serving |

Child stderr is discarded; bounded stdout is parsed for phase results only and
never persisted. Process failure, timeout, malformed result, semantic refusal
and local error use safe codes rather than copied diagnostics. Failed attempts
leave the reader alone and wait for the next due attempt; credential rotation
and compatibility checks remain in the helper. Do not delete status to force
another capture. Changed cadence applies on the next controller start; the
persisted `next_due_at` describes the cadence recorded at the last attempt.

The helper, consumer and producer must have compatible identities. A frozen
schema78 consumer cannot be paired with a main/schema80 helper; configure a
compatible installed pair in an isolated root and retain the old warm reader
until that new candidate is ready. This PR supplies fake-process orchestration
tests, not actual hosted captures, source-history qualification, restart proof,
live audits, or deployed acceptance measurements.

## Keeping a verified Linux standby warm

Full startup admission repeats the history checks. On large databases, start
one owner-only local process ahead of an outage rather than starting it for
each agent. The Linux maintainer relay is:

```bash
python3 scripts/native-local-daemon.py serve \
  --socket /absolute/private/run/standby.sock \
  --consumer /absolute/installed/mcp-stdio \
  --config /absolute/runtime.json \
  --scratch /absolute/private/scratch \
  --account "<canonical-owner-account-token>"
```

The run and scratch directories must be mode 0700 and owned by the current
user. The relay holds an exclusive owner-only lock, starts the official
consumer with socket/connect syscalls denied, and listens on a mode 0600 Unix
socket only after startup completes and `records_read` is available. It refuses
a status-only consumer. Select the owner canonical account explicitly with
`--account`; HQ contains multiple accounts. Missing selection is refused before
starting expensive admission; the official consumer validates the selection.
Data reads and write refusals go unchanged through the official kernel;
the relay serializes requests to keep responses with the correct client even
when clients reuse JSON-RPC IDs. Engine EOF or a lost response stops the relay
rather than routing subsequent responses incorrectly. Startup allows 90 minutes, accommodating the measured 42-minute HQ admission;
ordinary requests allow 120 seconds.

The relay owns a deliberately limited discovery/metadata frontend. Its local
`bootstrap` calls an authorised kernel `records_read.get_record` for
`native:root`, returning the kernel's `standby_context` unchanged alongside
`bootstrap_scope: local_serving_metadata_only`. It reports mode, read-only
availability and actual serving snapshot age. It creates no run key, intent,
personal orientation or durable context, and is not canonical Native bootstrap.
Optional string `run_key` and `parent_key` are accepted but ignored for this
metadata-only call. The fresh stdio connection strips those keys on bootstrap
before sending to the socket, allowing a warm older daemon to keep serving
while the client compatibility fix is installed; all data-call envelopes remain
unchanged. Older warm daemons may still advertise only the format field until
their next planned restart.
Missing context or an authorisation failure produces an error, never an invented
healthy status. Discovery and initialization explicitly describe this scope.

In the current official consumer, full `standby_status` and
`system_read.engine_info` repeat complete verification of all retained
generations. The relay replaces `standby_status` with bounded local metadata
and refuses engine-info calls with `LOCAL_FULL_AUDIT_SEPARATE`, so full audits
cannot block the shared read connection for tens of minutes. Other system reads
(including ping), record reads and writes retain kernel handling. The context's
`full_status_tool` still names the official tool; the local bootstrap's
`full_status_route` explains that it requires a separate official consumer:
start the installed consumer with `--standby --account <owner> <runtime-config>`
and call `standby_status`. That process has its own full startup and audit cost.

Configure each agent's `native-local` MCP command as:

```bash
python3 scripts/native-local-daemon.py stdio \
  --socket /absolute/private/run/standby.sock
```

The server leases one immutable generation. Its status reports that serving
generation's actual age even if a newer one has been accepted. A refresh
controller can request a replacement through a separate owner-only control
socket. The relay starts a new network-denied official consumer, waits for
kernel readiness, requires the requested serving generation and a real
`STANDBY_READ_ONLY` write refusal, then swaps readers between requests.
Existing client connections stay open. Failed startup or verification keeps
the old reader serving. Restarting the daemon revalidates and selects a
generation; the relay does not bypass that startup check. Keep
hosted Native as the normal canonical connection. An unavailable relay must
remain unavailable, with no raw database or hosted proxy fallback.

### Running scheduled refresh on Linux

Use the external full-copy controller described above with the service
templates in `scripts/systemd/`. The default cadence is six hours after an
attempt finishes, configurable as `cadence_seconds` in `scheduled-refresh.json`.
There is no catch-up queue or overlapping attempt. Full acquisition still
loads hosted Native, so record the first refresh's acquisition, admission and
activation durations, snapshot bytes and visible hosted latency
before shortening the cadence. This route does not promise a five-minute RPO.

Prepare a compatible installed consumer and admission helper, a private
runtime root, and private `run/live` and `scratch` directories.
Keep the independent credential-renewal service running. Install the daemon,
controller and service templates under the paths named in the templates.
The owner-only `reader.env` supplies `NATIVE_LOCAL_CONSUMER`,
`NATIVE_LOCAL_RUNTIME_CONFIG` and `NATIVE_LOCAL_OWNER_ACCOUNT`; it contains no
hosted bearer token. Set `NATIVE_LOCAL_SEED_SOCKET` to the existing warm
owner-only relay socket for the first installation, or to an empty string for
ordinary kernel startup. The seed supplies actual kernel reads; a status file
cannot certify it. Use the seed only during installation and clear that
setting after the first successful refresh, before enabling the reader at boot.

Add `activation_socket` pointing to `run/live/control.sock` and `status_file`
pointing to `refresh-status.json` to the controller configuration. Start the
new reader service and verify local metadata while the original service stays
available. Configure new MCP sessions to use the stable `run/live/standby.sock`.
Then disable the old snapshot timer and start `native-local-refresh.service`;
it performs the first attempt and subsequently observes the persisted
cooldown. Enable both services for boot after the first successful activation.
Leave existing agent sessions on the old relay until they reconnect.

Bootstrap and the local `standby_status` return the serving kernel's actual
`freshness.age_seconds`, alongside advisory `refresh` information including
`last_failed_attempt_at` and the failed phase. That failure timestamp survives
a later successful attempt. Missing or malformed status reports
`status_available: false` while kernel reads and truthful age remain available.
The separate official consumer remains the route for exhaustive status audits.

## Rejected first-release alternatives

- A mutable working copy like the emergency recovery environment: it can fork
  canonical state and cannot provide the Milestone 1 safety claim.
- Copying a live SQLite file or synchronizing SQLite files bidirectionally:
  neither is a transactionally consistent reconciliation protocol.
- Treating R2 operator recovery as ordinary owner refresh: it exposes the wrong
  tenancy and credential boundary.
- Migrating promoted generations in place: it destroys immutable provenance
  and complicates rollback.
- Transparent failover in the first release: it can hide a change in authority
  and freshness from agents.
- Relying on tool discovery or filesystem mode alone: exact dispatch and an
  already-open writable connection remain bypasses.
