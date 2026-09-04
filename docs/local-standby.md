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
read-log, job, run, and receiver-local relationship-quarantine bookkeeping is
disposable and is never replayed locally. The in-place storage-portability
policy is conservatively frozen byte-for-byte across promotion until it gains
a ratified history or successor proof; semantic validation alone cannot prove
that a higher revision belongs to the same lineage.

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
