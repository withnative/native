# Full-owner local standby contract

This document fixes the Milestone 1 dogfood contract for a full Native owner
replica on one trusted laptop. It is a read-continuity release: hosted Native
remains the canonical authority, and the local process cannot author canonical
state or claim that offline writes are supported.

This is the human-readable contract boundary for the first implementation
slices. The snapshot producer, closed provenance schema, offline
accept/promote kernel, startup activation/recovery path, and refresh controller
are implemented, including durable range resume and status disclosure. Shipping
qualification remains a separate release concern.

## Release-pinned acquisition

The 0.1.1 commands below describe the prepared Mac-capable candidate. They
are not executable public delivery instructions until that exact wrapper and
platform version are qualified and published. Public 0.1.0 selects Linux only.

The supported laptop path is the `@withnative/standby` npm package at an
exact version. Its platform-specific optional dependency contains a prebuilt
`mcp-stdio`, plus a `native.standby-artifact.v1` manifest with the full
`NATIVE_CE_GIT_SHA`, engine schema version, frozen DDL fingerprint, and binary
SHA-256. The package verifies that manifest and checksum before copying the
binary into an immutable versioned generation under
`~/.local/share/native-local` (or `NATIVE_STANDBY_HOME`). A clean laptop does
not compile the repository.

```sh
npx --package @withnative/standby@0.1.1 native-standby install
npx --package @withnative/standby@0.1.1 native-standby configure \
  --replica-root "$HOME/.local/share/native-local" \
  --hosted-route ROUTE_DATABASE_ID \
  --origin-database-id ndb_DATABASE_ID \
  --mcp-config "$HOME/.config/mcp/config.json"
npx --package @withnative/standby@0.1.1 native-standby verify --json
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
- The local copy trusts the authenticated server. It starts from one whole
  snapshot (the checkpoint) and then applies hosted Native's changes to itself
  in place, a whole act at a time. Deep verification is an explicit audit, never
  part of a refresh.
- While the laptop is awake and online, refresh runs every **minute** by default
  and is also attempted immediately on startup, wake, and network recovery. A
  refresh with no hosted change is one cheap head probe. A copy last found
  current more than **5 minutes** ago is beyond the dogfood recovery-point
  objective (RPO). Reads remain available beyond RPO, but every status surface
  must say so plainly.
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

### Installed-app reads through Desktop main

Desktop main may carry an installed v2 app identity in an owner standby
`tools/call` request, outside operation arguments:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "sql_read",
    "arguments": {
      "operation": "query_sql",
      "arguments": { "sql": "SELECT id, name FROM records LIMIT 20" }
    },
    "_meta": { "native/app": "agent.docs@1.0.0; install=install-event-id" }
  }
}
```

The value uses the existing `X-Native-App` identity grammar. It is preserved
through legacy and modern MCP, including executor delegation. Main retains
credentials, account selection and renderer/session fences. This field never
selects an account or grants authority. Engine admission requires the selected
account's current installed v2 package, version and install event in the admitted
copy, with `shell_adopt.v1` or `shell_auto.v1` adoption. Apps use the same governed
user reads, including logical-relation SQL, without scopes, needs or grants.
App approval and egress exceptions remain; offline writes remain read-only.

Install and app-operation refusals are ordinary tool results:
`result.isError: true` with `result.structuredContent.error`. Malformed metadata
and use of this carrier on writable stdio are JSON-RPC `INVALID_PARAMS` errors.
Desktop preserves ordinary tool refusals as `TOOL_ERROR` status 400; a JSON-RPC
failure is a transport failure, not an app-install verdict.

This requires a runtime built with the carrier implementation and a compatible
admitted generation. Older standby binaries ignore unknown metadata and cannot
qualify attributed-app support. Do not pair a changed binary with an incompatible
snapshot, relabel a frozen trial, or claim a prior unattributed read as evidence
of this contract.

The owner explicitly authorizes a complete workspace copy on one Linux x86_64
laptop they control. Mutable replica directories are owner-only (`0700`) and
files are owner-only (`0600`); a published generation is tightened to `0500` and
`0400`, and the current generation's directory and database return to `0700`
and `0600` when the first delta advances them. Full-disk encryption is a supported-use prerequisite,
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
      <generation>/
        snapshot.db                # the checkpoint, then advanced in place
        manifest.json              # immutable: describes the checkpoint
    heads/
      <generation>.json            # head act, sync time, snapshot|delta
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
makes the generation durable, then atomically replaces `current.json`. Interruption leaves either the old or new verified generation
current. Ordinary refusal removes its `.publishing-*` workspace; a crash may
leave one behind, but it is never authoritative or addressable through
`current.json`. Refresh and retention may replace only `accepted/`; they never
remove or rewrite `device/`.

Every process start reads a strict external standby configuration which binds
an absolute replica root to the expected hosted route and portable origin. It
hashes the executable bytes through `/proc/self/exe`, then re-verifies current
against that observed installed identity before serving data. A generation
that deltas have advanced no longer matches its checkpoint digest; it is
verified from one consistent private copy against the checkpoint's identity,
schema and act instead. Current is verified first. Older priors are verified
after the node publishes a ready reader, on a separate background runtime,
and lazily when selected as fallbacks. Even excess retention does not delay
serving a healthy current. Newer durable candidates
are still checked for successor recovery. If current fails,
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
to current plus two prior generations in background maintenance after reader
publication or a whole-snapshot install, or an explicit retention pass.
Maintenance reuses current's completed selection/admission/validated-delta
observation, re-verifying current if that observation is lost. When excess
copies require pruning, it freshly device-checks two good priors newest-first
before the first deletion, then freshly verifies each actual deletion candidate.
The metadata cache never establishes the retention floor for deletion.
Background maintenance also checks retained priors when there is nothing to prune; an explicit prune-only pass with at most
three directories does no database verification. Corrupt or unverified copies
are left in place. Discovery and pathname pinning hold the promotion lock only
briefly; all database checks run outside it. Before deletion, maintenance takes
the lock again and checks the selected pointer, current's verdict, two protected
unchanged priors, the deletion candidate's unchanged checked inputs and its
exclusive nonblocking lease. Pointer or input changes defer deletion.
Interrupted `.pruning-*` workspaces are finished
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
minute, or every `refresh_interval_seconds` when the refresh configuration sets
it. The interval uses delayed-tick behaviour: suspension does not
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

That two-positional invocation is the operator/manual form and keeps
`RefreshCause::Manual` semantics, including its deliberate exemption from the
minimum interval between whole snapshots. An automatic driver that is reacting
to an invalidation hint must instead name its cause explicitly, so a persistent
delta refusal cannot turn a stream of hints into repeated database-sized
captures:

```
mcp-stdio --standby-refresh /path/to/standby.json /path/to/refresh.json \
  --cause scheduled|after_admitted_write|network_recovery|wake
```

`--cause` accepts exactly those four automatic causes; `manual` is not a valid
token because the two-positional form already selects it. The whole command
line is validated before any configuration is read, a controller is created, or
a network attempt begins, so a missing, duplicated, unknown, or unsupported
selector fails closed without side effects. When a running standby process
already owns the daemon lock, the selected cause joins the durable coalesced
trigger set through the same `request_refresh(cause)` seam; otherwise the
one-shot run performs `refresh_once(cause)`. Either way the selected automatic
cause retains the six-hour FULL-snapshot throttle, while Manual retains its
repair bypass. The existing `Installed`/`Unchanged`/`Deferred`/`Advanced`/
`Accepted` diagnostics are unchanged; only the cause label in the one-shot
message reflects the selection.

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

Every full snapshot acquisition, including delta fallback, prefers the hosted
v2 snapshot route with gzip level 1. Only an empty initial v2 start 404 without
an export API or `Content-Encoding` header permits compatibility with the v1
identity route. A structured database/handle 404, generic 400, contract mismatch, authentication,
compatibility, capacity or integrity refusal never starts an identity capture.
Each retained export remembers its owning protocol; restarting cannot change
that protocol. A known legacy v1 record continues to use v1.

The binary route allows up to 30 minutes for hosted capture,
filtering, verification and hashing. The local refresh attempt allows 45
minutes including transfer and local verification. Individual binary HTTP requests
allow 60 seconds in total with a 5-second connect limit. The downloader runs at
most four concurrent 1 MiB ranges, holding at most 4 MiB of collected range
bodies plus bounded transport and ledger overhead. Range retries remain bounded
and apply only to network/timeout failures; authentication, protocol and integrity
refusals are not retried. Capture
single-flight, retained-export limits and owner checks still apply. These are
acquisition budgets, not measured HQ timings or a five-minute freshness promise.
An expired handle does not interrupt SQLite capture; its resource lease lasts
until capture and cleanup finish. Do not repeatedly start new full captures
when seeding fails.

Resume is built into the refresh controller; the configuration shape is unchanged.
It atomically saves the owned protocol-bound pending capture before polling,
then keeps a route/origin/consumer-bound manifest and sorted range ledger beside a fixed private partial file in
`refresh/`. One coordinator validates every 206 response, writes and fsyncs the
completed range, hashes it, and atomically saves the ledger before counting it.
Interrupted, timed-out or exhausted transient transfers retain this local custody
and do not cancel or silently start another export. A later controller re-reads
credentials, performs an authorized poll even when every range is cached, compares
the complete saved manifest and both byte identities, and rehashes cached ranges
before downloading only missing ranges. For gzip, ranges, range hashes, ETags,
response totals and byte progress all address the encoded bytes. The ready
record persists encoded size/SHA separately from the unchanged decoded
manifest/size/SHA; it never relabels an encoded partial as identity bytes.

After transfer, the client verifies the complete encoded identity before a
fixed-buffer, single-member gzip decode. It requires exact decoded size/SHA,
checks the footer and refuses trailing bytes and additional members, including
empty members. HTTP bytes use `application/gzip` without `Content-Encoding`;
implicit HTTP decompression is disabled. The decoded SQLite file then goes
through the same consumer, SQLite/FK, structural, predecessor and atomic
publication checks as identity-v1. These verification passes remain distinct.
Hashing, range persistence and decoding run in owned blocking work. Aborting
its waiter retains the work lease through file cleanup; another attempt cannot
write the fixed partial until that work finishes.

A live retained export can resume inside the FULL cooldown without spending another
capture. If it expires or is lost after a server restart, local custody is cleared:
one replacement capture is allowed only when the ordinary capture budget permits
it (including a manual request or first install). Inside cooldown it defers instead.
Terminal protocol/integrity refusal clears owned custody, propagates cleanup errors,
and attempts authorized cancellation; it never captures again in that same attempt.
Authentication or connectivity failures preserve custody for later authorized reuse.

This acquisition path remains consumer-bound. The broader filtered-without-consumer
and logical-relations companion work tracked by `598a06c` remains open.

A reproducible synthetic fixture encodes 300,000 bytes with byte `i` equal to
`i % 251`, using gzip level 1. It produced 2,913 encoded bytes: an
encoded/decoded ratio of 0.009710 (0.971%). This deliberately repetitive fixture
checks the bounded decoder across buffers; it is not a database capture or a
WAN throughput measurement. Reproduce the byte counts with:

```bash
cargo test -p native-ce --lib -- \
  standby::refresh::transfer_repr::tests::decode_roundtrip_spans_buffers \
  --exact --nocapture --test-threads=1
```

An initial capture may outlast an OAuth access token. Binary start (including
the compatibility request), polling, range
requests, retries and cancellation re-read the guarded credential file, so a
separate owner credential controller can atomically renew it without restarting
the capture. The runtime does not itself hold an OAuth refresh grant.

A long-running host should use a separate owner-authorized credential controller
with its own refresh grant. Do not share a rotating OAuth grant with an active
MCP client. Renewals should be serialized, private and atomically published;
revoked grants require owner sign-in again. Authentication renewal must not
capture snapshots or change canonical workspace data.

A refresh takes a whole snapshot only on first install or as a fallback (see
below). Ordinary fallbacks that replace an existing copy wait at least six
hours from the previous FULL start (`full_refresh_min_interval_seconds`;
the external scheduler's `full_interval_seconds`), whatever its outcome. A
persistent ordinary fallback therefore costs one database-sized capture per
interval, not one per minute. Manual refreshes bypass this hold. Consumer-change
and failed-audit repairs run immediately after a successful FULL. After a failed
FULL, those repairs wait `full_refresh_repair_retry_seconds` (default thirty
minutes) from the failure's end, so slow failures and timeouts still get a pause.
If the failure end is missing or invalid, the hold counts from the FULL start;
a retained failure end older than that start cannot shorten it. Future timestamps
hold the retry too. The repair interval has a sixty-second floor and is capped
by the ordinary minimum; explicitly setting `full_refresh_min_interval_seconds`
to zero disables both holds.

`StandbyRefreshConfig` rejects unknown fields. Adding
`full_refresh_repair_retry_seconds` to the config prevents rollback to an older
binary that does not recognize it; remove the field before that rollback.

Waiting is recorded as a deferral (`last_deferral: full_refresh_interval`),
not a failure; the copy keeps serving and its reported freshness ages honestly.

Deltas also wait, without failing, until a build that reads the current
generation as an ordinary SQLite file is serving it. Such a serving process
holds a shared `flock` on `accepted/heads/<generation>.reader.lock` for as long
as it serves the generation, and records its source SHA in
`accepted/heads/<generation>.reader.json` after it has swapped the generation
in. A delta is applied only when the marker matches the refresh controller's
installed consumer and the lock is currently held (the controller probes it
with a non-blocking exclusive lock and releases it at once), so a marker left
by a cancelled or crashed process, or by a reader that has since been replaced,
never counts (`last_deferral: reader_not_upgraded` until then). Consumers built
before in-place deltas open generations `immutable` and would read pages a delta
rewrites. If deltas stay deferred this way for more than ten consecutive ticks
(about ten minutes at the default cadence), `standby_status` and the bootstrap
context report `reader_not_upgraded` as a degraded reason with the next step
"restart the local Native connection so the new build serves this copy".
Manually activating a new consumer onto the *same* generation an old consumer
is still serving can let a delta land before the swap; the supported scheduler
path holds one lock across activation and deltas, which avoids this.

A changed binary can locally re-admit the same generation when platform,
engine schema, frozen DDL and native interchange revision match. Startup and
delta run the existing device verification: generation identity, route/origin,
manifest and exact checkpoint bytes for an unadvanced copy; a consistent
private copy with engine/frontier and SQLite checks for an advanced copy.
Exhaustive conformance replay remains an explicit audit. No download or hosted
capture is needed. Format mismatches or failed re-admission retain the whole
snapshot fallback (`consumer_changed`). The live-reader gate above still applies.

Re-admission preserves `manifest.json` and `heads/<generation>.json`. It atomically
records the original consumer, newly observed consumer, revision, acceptance time
and completed checks in owner-only
`accepted/heads/<generation>.consumer-rebind-<artifact-sha256>.json`. The sidecar has a checksum
for accidental edits, not a signature; checksum or identity mismatches refuse.
Unrecognized contracts, versions, check lists or fields require fresh verification
before replacing only that consumer's receipt. Receipts for other consumers
coexist until pruning; status inspection never publishes a binding. Startup
verifies each retained candidate once, reusing a successful rebind verification.
Local I/O, disk, lock or cancellation failures remain retryable local failures;
they do not request a `consumer_changed` FULL. Owned temporary receipts left by
interrupted publication are cleaned without deleting active publishers' files.
Every installed-generation verifier accepts
the original exact consumer or valid evidence for the observed binary, then runs
its ordinary copy checks. Full status includes `consumer_rebind` alongside the
original consumer; response context includes `serving_consumer_rebound_at`.
Re-binding alone is not a degraded state.

Rollback to the exact original manifest consumer remains supported, including
after the replacement applies deltas: identical schema, DDL and interchange
revision preserve the readable format, and the older consumer repeats its normal
checks. It ignores the sidecar. The exact DDL hash fences on-disk compatibility.
The frozen release
schema-to-revision mapping is an additional build compatibility assertion, not
revision evidence from the original copy: the manifest has no revision field;
unknown mappings or disagreement with this build refuse re-binding. Incompatible
format changes must update a format coordinate. The immutable-reader delta gate
relies on no pre-delta build sharing the current schema/DDL/revision format;
future reader-semantics changes must change a format coordinate. Re-binding is
safe to do locally because the manifest's consumer is the client's own
declaration: hosted validates only its structure and schema/DDL compatibility,
never the artifact hash.

If a serving read holds the database past the writer's 60-second wait, the delta
commit fails as SQLite busy or locked. That rolls back, writes nothing, and is
recorded as a deferral (`last_deferral: database_busy`); the same delta is tried
on the next tick. It does not fall back to a whole snapshot. If that repeats for
more than ten consecutive ticks, status reports `database_busy` as a degraded
reason with the next step "a local read has held the copy open for a long time;
restart the local Native connection".

The consecutive counts behind these two degraded reasons live in a sidecar,
`accepted/heads/<generation>.deferrals`, not in the head record
(`<generation>.json`), which older builds parse strictly and must keep
parsing. The controller likewise keeps whether the last whole snapshot
completed in `refresh/last-full-outcome`, marked failed when a snapshot starts
and completed when it is installed.

One-shot repairs do not wait out the six-hour interval. A whole snapshot whose
reason is a failed audit (`audit_failed`), a changed installed consumer
(`consumer_changed`, when local re-admission is incompatible or fails) or an operator's manual refresh runs on the next attempt,
still one at a time. Persistent reasons (a refused head, an oversize delta, pin
drift, a gap) keep the interval. A repair that follows a whole snapshot that
failed or was interrupted (the recorded outcome, not a timestamp comparison) does wait, so a repair that keeps failing is not a
database-sized capture every minute; a manual refresh never waits.

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

`standby_status` and bootstrap's existing refresh diagnostics include optional
`transfer_progress`: `following`, `capture`, `download`, `verification`, or
`publication`, with an observation timestamp and `active`, `inactive`,
`interrupted`, or `stale` activity. Stage transitions publish immediately; byte
updates during transfer are coalesced to at most once per second, with an immediate
completion update and a thirty-second heartbeat while authorized capture polls
remain pending. Advisory observations use bounded,
atomic `refresh/transfer-progress.json` replacements tied to the attempt ID, without
an extra fsync per read or replacement of durable scheduling state. They can be
lost after a crash; the ledger remains the resume authority. Completed/remaining/total bytes count validated, durably saved ranges,
including revalidated cached ranges; in-flight bytes are excluded. Gzip reports
encoded network bytes, rather than the expanded SQLite size. Capture has no
known total. `retained_for_resume` means local custody exists, not that the server
has authorized reuse or that the candidate is admitted. Inactive/interrupted
counters describe retained local work; a resumed attempt revalidates it. An active
observation older than two minutes (or inconsistent with the clock) is marked stale;
loss of the attempt lock is reported as interruption. No bearer, export handle,
raw path or workspace content is included. Missing optional progress in older
state remains supported; impossible counters make diagnostics unavailable.
Completion, failure, timeout, cancellation and deferral clear active progress.
Neither byte completion nor verification/publication activity advances the accepted
copy's freshness: that remains derived from a successfully published generation.

A delta lands in the generation the running MCP process already serves, so
its next read sees it. A whole snapshot produces a new generation instead; a
running process keeps its startup-selected generation and lease until a restart
or relay activation. Status must distinguish the generation currently being
served from a newer accepted pointer when they differ.

Only the refresh controller writes to a generation, and only through the
authenticated delta apply. It performs no schema migration: a delta whose
schema or DDL differs from the local copy is refused and takes the whole-snapshot
path.

The serving runtime opens its SQLite connections with SQLite's physical
read-only flag (not `immutable`, so ordinary locking shows each read the state
before or after a delta), performs no migrations or startup repair, and
suppresses read-interaction capture and run/intent persistence. Filesystem
permissions are defence in depth, not the enforcement boundary.

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

Steady-state refresh probes the authenticated authority act head. An equal
head is a no-op: one probe, no hashing, no verification, and the copy's sync
time moves forward. An advance fetches one bounded, authenticated whole-act
delta and applies it to the current generation's database in one SQLite write
transaction, through the same per-event projectors and DDL triggers used by the
authority. Inside that transaction the materialiser checks that the delta
starts exactly at the copy's head, that origin and pins match, that every
section fits the local schema, and that the result re-exports to exactly the
carried rows. Any refusal rolls the transaction back. There is no base
re-verification, clone, rehash or re-admission on this path.

A whole snapshot is a checkpoint at its head act. Deltas after it are complete
whatever the database's source-history marker (`PRAGMA application_id`) says
about the history before it. Hosted Native therefore serves `authority_act_head`
and `authority_act_delta` for history-unknown databases such as Native HQ, and
the copy reports that earlier history honestly as `unknown`. Nothing rewrites
or relabels the marker.

**Fallback rule.** A gap, schema or DDL mismatch, identity or pin change, auth
or epoch change, an oversize delta, or any apply error rolls back and takes the
whole-snapshot path. A failed fallback leaves the current copy serving
unchanged. A whole snapshot replacing a copy that deltas advanced (or an audit
found bad) is not fenced by that copy's own rows: only route, origin and act
order must hold, because the snapshot is how that copy is repaired.

Each generation's head record (`accepted/heads/<generation>.json`) holds the
act the copy holds, when hosted Native was last observed at that act, and
whether deltas have advanced it (`materialization: delta`). It is marked before
the first delta changes any byte, so verification never mistakes an advanced
copy for a corrupted checkpoint.

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

A checkpoint's freshness uses `captured_at`, sampled immediately before
`VACUUM INTO`. After that, the head record's `synced_at` (sampled before the
head probe that found the copy current, or that led to the delta which made it
so) is the conservative RPO boundary. `snapshot_completed_at` reports later
SQLite snapshot verification completion and must not make an old capture
appear fresher.

## Milestone 1 MCP surface

The hosted snapshot producer, local offline accept/promote kernel, and local
startup activation path are implemented. The kernel verifies staged bytes and
manifest evidence, performs rollback and projection checks, publishes
generations, and switches its durable current pointer atomically. `mcp-stdio`
resolves that pointer through a strict standby runtime config, revalidates the
selected generation, falls back safely, holds an active-generation lease, and
prunes only unleased known-good generations. With no usable generation it runs
a database-less MCP exposing only bootstrap and `standby_status`; every exact
snapshot-backed call fails with `STANDBY_STATUS_ONLY`. Configured network
refresh advances the current generation in place and, on fallback, acquires
and promotes a new one; only the refresh controller writes, and the serving
connections stay physically read-only. Bootstrap, `engine_info`, and the dedicated
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
they do not relax direct writes to an accepted generation.

## Honest status and independent failures

Bootstrap and the status read share the versioned status shape. They report
standby or status-only mode, read-only/write capability, hosted canonical
authority, hosted route database ID, portable `origin_database_id`, the
process-leased serving generation separately from the dynamically accepted
generation, snapshot and promotion times, frontier, each generation's
`head_act`, `materialization` (`snapshot` until the first delta, then
`delta`), `synced_at`, and `source_history` (`exhaustive`, or `unknown` for a
checkpoint whose earlier history is not known to be complete, as on Native HQ),
consumer artifact and engine/schema compatibility, last attempted and
successful refreshes, refresh activity, age, target cadence/RPO, explicit
fresh/stale and beyond-RPO state, retained generations, startup fallback, and
the last safe refresh failure.

Every successful snapshot-backed read also carries a compact standby context.
It identifies the hosted canonical authority, the leased serving generation
with its live `serving_head_act`, `serving_materialization` and
`serving_source_history`, and freshness derived from the later of that
generation's `captured_at` and `synced_at`. The
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
  authenticated refresh. Milestone 1 performs no reverse upload or SQLite file
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
`GenerationStore::install_staged`: route, origin, consumer, snapshot identity
(size/SHA-256), supported-schema compatibility, SQLite `quick_check` with
foreign keys, read-only safety, continuity, and atomic publication checks
remain in force. Per ratified decision e15d82a, full conformance
(rebuild-and-diff, exhaustive relationship history) and awareness
reconstruction are not device gates at admission or startup; they live on the
hosted side and in CI. The deliberate off-path audit retains those deep checks
as an opt-in early warning, never as a serving gate. It never rewrites the manifest or marks history qualified. Fresh downloaded snapshots still require the exact observed consumer. Installed
generations may separately pass the same-format re-admission described above;
this never relabels the original download.

Offline admission writes aggregate verification progress to stderr while retaining
its final JSON receipt on stdout. Named phases distinguish the candidate,
predecessor, snapshot identity/state/`quick_check` damage checks, and successor
fence. The standby consumer also writes these
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
admission. This separates the network attempt's 45-minute budget from later
offline verification and admission.

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
disk space. An interrupted transfer retains the built-in export/partial custody
for authorized resume; terminal refusal or successful consumption attempts
best-effort cancellation. Producer expiry remains the backstop. Do not blindly
start another capture.

Run the default offline command with those returned paths, keeping the existing
verified reader running. Complete kernel admission remains mandatory before
publication. Admission atomically updates the current pointer; an already warm
reader keeps its leased old generation until a separately verified replacement
is ready. Neither acquisition nor admission automatically replaces that process
or enables a refresh timer.

## Legacy-link delta recovery and rolling upgrades (8134d50)

The v1 act-delta inventory omitted `provenance_local_attestation_authority`.
Whole snapshots retained these authority-local anchors, but later deltas carried
new attestations and outputs without their anchors. Relationship replay already
invoked the compatibility-link projector; missing verified admission instead
left new assertions unresolved and their `links` rows absent. A fresh delta
sync time therefore did not prove projection completeness.

The v2 delta contract carries only existing anchors reached through the same
bounded attestation closure as the other provenance companions. The authenticated
transport and pinned same-database origin remain load-bearing. Anchors are never
minted from issuer claims and remain excluded from portable interchange; foreign
or imported attestations without local issuance evidence stay unresolved.

Generation-head version 2 marks use of the corrected delta fold. Version 1
heads remain readable, but a v1 head with `materialization: delta` requests a
whole snapshot before the equal-head fast path and refuses in-place writing.
A consumer rebind does not upgrade that marker. This is conservative: every
v1 delta-derived generation is replaced, even if its particular history did
not encounter the bug. A v1 untouched snapshot can enter the corrected fold;
the writer marks its head v2 before changing the database. This is a refresh
recovery boundary, not a new startup or serving gate: an already served old
copy can remain available until the verified replacement is activated.

Rebuild-and-diff is insufficient to establish recovery: relationship rebuild
uses the copy's own issuance anchors and can agree with a consistently
unresolved projection. Content rebuild treats relationship links as external
inputs. The focused regression demonstrates both rebuilds passing a missing-
anchor copy, an unrelated v2 delta preserving that historical gap, and a whole
snapshot restoring exact raw links and anchors. Do not edit replica tables,
infer anchors from attestations, or rely on a binary swap or generic manual
refresh to backfill history.

For an explicit FULL, use the `standby_admit --acquire-only` command above,
then admit that returned snapshot/manifest pair with the offline admission
command and use the normal verified activation path. `--acquire-only` explicitly
bypasses delta selection; a normal manual refresh may still choose a delta.
Retain the current verified copy until replacement succeeds. The scheduled
controller can also follow the new recovery fallback; its FULL cooldown and
successful admission/activation rules still apply. A fresh capture/admission
alone is not proof that a client is serving the replacement. This source change
does not operate the installed node or qualify a live recovery.

During a rolling upgrade, old-node/new-hosted and new-node/old-hosted pairs
refuse the other delta contract rather than silently omit authority evidence.
The refresh controller classifies that integrity refusal as a whole-snapshot
fallback (subject to the existing FULL scheduling rules); hosted head/schema
compatibility is still checked first. Repeated cross-version delta attempts can
therefore request repeated FULLs until both ends are upgraded. A head match
can avoid a delta request, so wire-version refusal alone cannot repair an old
high-head copy; the generation-head guard supplies that recovery on new nodes.
An old executable also refuses a v2 generation head; downgrade requires the
ordinary verified snapshot/replacement process, never relabelling its head.
The regression covers new-reader refusal of the complete v1 inventory and
refusal of merely relabelled v1 bytes. Old-reader refusal of v2 follows its
closed v1 contract/version and inventory checks; no old installed binary was
run as part of this source qualification.

Compare raw projections only with raw projections at the same authority head.
Physical links may retain soft-deleted endpoints, while caller-visible reads
exclude deleted or hidden records. The deletion regression preserves those raw
rows on both primary and standby. Raw owner-copy counts versus hosted
caller-visible counts cannot by themselves establish stale surplus; the
reported production surplus remains unclassified by this source investigation.

## External scheduled refresh

`scripts/native-local-refresh.py` keeps a relay-served copy current. It invokes
an **already installed, compatible** `standby_admit` helper. Each tick runs one
authenticated `--delta <runtime> <consumer> <refresh>` call, which applies at
most one whole-act delta in place to the copy the relay already serves, or
reports `full_refresh_required` with a reason. Only then does the tick run the
full-copy pipeline: one `--acquire-only <runtime> <consumer> <refresh>` call,
offline `<runtime> <consumer> <snapshot> <manifest>` admission, and relay
activation. Every existing FULL acceptance check remains mandatory on that
path. The controller never reads credentials: the refresh config names the
guarded credential file; do not put a token in controller config, argv, or
environment.

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
  "cadence_seconds": 60,
  "full_interval_seconds": 21600
}
```

Run `python3 scripts/native-local-refresh.py once --config /private/standby/controller.json`
for one due attempt, or use `serve` for an asynchronous scheduling loop. `once`
honours cadence; it has no force/retry option. The first invocation is due
immediately; later ticks wait `cadence_seconds` (default **60**) after the
previous one finished, with no catch-up on wake or network recovery. A full
copy may start only `full_interval_seconds` (default six hours) after the
previous one started, whatever its outcome; the next due time is persisted
before any capture begins. The exception is a repair (`audit_failed` or
`consumer_changed`) after a full copy that succeeded, which starts on the next
tick, still under the one controller lock. Ticks inside that interval that would
need a full copy record `state: deferred` with `deferred_reason: full_interval`, as do
delta helper deferrals (for example `reader_not_upgraded`). Neither counts as
a failure. A delta-phase failure (network, authentication) never starts a full
copy.

A nonblocking cross-process `flock` at
`<replica_root>/refresh/scheduled-controller.lock` covers acquisition, FULL
admission, activation, status and cleanup. Children inherit the lock so a
surviving phase continues to exclude another controller. Use one controller
config/status path per replica: the lock binds that path and refuses another
status history. The existing helper separately refuses competing built-in
acquisition/refresh attempts. Do not run a built-in refresh daemon alongside
this controller. Helper wrappers must retain inherited descriptors and remain
in their process group; detaching work breaks that lifetime contract.

Default phase deadlines are five minutes for a delta, 46 minutes for
acquisition (the helper retains its own 45-minute network budget), two hours
for offline admission, and three hours for activation. Optional
`delta_timeout_seconds`, `acquire_timeout_seconds`, `admit_timeout_seconds` and
`activate_timeout_seconds` override them. A delta killed mid-apply leaves only
SQLite's rollback journal, which the next delta rolls back before reading. Timeout or cancellation kills the
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
| `state` | `running`, `failed`, `deferred`, or `succeeded` |
| `phase`, `completed_phase` | Current/last attempted phase and last completed phase (`delta`, `acquire`, `admit`, `activate`); completion may be null |
| `last_attempt_at`, `finished_at` | UTC attempt-start and completion timestamps; completion is null while running |
| `last_failed_attempt_at` | Start of latest failed attempt, retained after later success |
| `last_failure_phase`, `last_failure_error_code` | Retained failure phase and fixed safe controller code; no raw child errors |
| `last_successful_attempt_at` | Start of latest successful tick (a delta tick, or a fully activated full copy), initially null |
| `head_act`, `full_refresh_reason` | Act the copy holds after a delta tick; why the delta helper asked for a full copy |
| `next_full_due_at` | Earliest UTC time another full copy may start, set when one starts whatever its outcome |
| `deferred_reason` | Why a `deferred` tick changed nothing: `full_interval`, or the delta helper's reason (`reader_not_upgraded`, `checkpoint_being_verified`, `database_busy`) |
| `last_full_outcome` | `succeeded`, or `failed` while a full copy has started and not yet been activated (a failed or interrupted one); a repair waits the interval after `failed` |
| `cadence_seconds`, `next_due_at` | Configured cooldown and next eligible UTC time; next due is null during work |
| `durations_seconds` | Measured subprocess elapsed times by phase, including failures, plus total elapsed time |
| `download_bytes` | Acquired snapshot file size from stat, initially null; not inferred from helper output |
| `generation_id` | The generation a delta advanced, or the admitted generation of a full copy; does not imply that it is serving |

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
until that new candidate is ready. `--delta` additionally requires the consumer
to be built from the same source as the helper, and defers every delta until
the relay's running consumer has opened the current generation (its serving
marker, above). Consumers built before in-place deltas open generations as
`immutable` and must never serve a copy that deltas advance, so deltas stay
deferred until the new consumer is installed and activated.

## Keeping a verified Linux standby warm

Full startup admission repeats the deep checks. On large databases, start
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

The official consumer's `standby_status` and `system_read.engine_info` use
process-local cached device observations, not fresh database verification.
Only completed matching checks count as usable; unseen/changed candidates are
reported with `unverified_candidate_count`, separately from
`unusable_candidate_count`. Unverified retained priors do not themselves degrade
the standby. An unverified current is disclosed as accepted provenance
`unverified`. The retained IDs/count cover matching good observations, not every
directory on disk. Infrastructure errors (I/O, full scratch disk, busy/locked
SQLite and cancellation) leave verification unknown, never a negative verdict.

The node and its own refresher share the same store/cache. After an authenticated
delta is validated, committed, closed and its head published, the refresher
advances a matching verified base to a distinct **verified-and-advanced** verdict
using the post-delta metadata. Thus `available` for the serving generation can
mean a device-verified base plus deltas the node itself validated. It does not
recheck or impersonate checkpoint verification. Ordinary trusted deltas and
no-change probes therefore preserve accepted provenance and healthy status. A changed descriptor/binding, failed
audit, absent verified base or unsuccessful apply cannot issue that verdict.

After a ready reader is published, a coalesced background worker checks retained
priors and performs safe excess pruning. Whole-snapshot installs also request
this work, without awaiting it on the refresh path. This worker uses its own
thread/runtime, per-generation leases and before/after observations, not a long
promotion lock. When current's cached verdict is unknown, maintenance
re-verifies it under its lease using the private-copy device check, at most once
every five minutes. A matching Invalid verdict is settled until its input stamp
changes. For this rare current-only recovery check, maintenance holds the
refresher's cross-process `refresh/attempt.lock`, preventing overlapping deltas
and briefly delaying refresh until the device check finishes (potentially
40–60 seconds for a large copy). It takes that lock before promotion coordination
and releases promotion coordination before checking the database. Prior checks
never hold `attempt.lock`. Other input changes still prevent an obsolete verdict.
Every refresh attempt can request another pass while current remains unknown,
subject to backoff, including after failure or rollback; shutdown cancellation
never schedules a retry. Excess pruning stops early if current is not known good.
Background infrastructure failures remain unknown until a later pass succeeds.

The cache starts empty in a new process. Pointer rewrites invalidate current's
entry; prior entries do not stamp unrelated pointer changes. Database, manifest,
consumer-receipt and substantive head changes otherwise invalidate observations;
a sync-time-only head update does not. Separate external writers cannot update
the running node's cache. A deployment where a separate process applies deltas
shows unverified until background verification completes. Metadata detects
ordinary file changes, not owner tampering; selection and deletion never trust
this cache. Pruning freshly checks both its prior floor and deletion candidates.
`observed_at` is sampled after the reported heads. The explicit deep audit remains an operator check; a separate
`standby_admit --audit` process cannot populate the running node's status cache
and is not a repair action for an unchecked prior.

The Linux relay still replaces `standby_status` with bounded local metadata
and refuses engine-info calls with `LOCAL_FULL_AUDIT_SEPARATE`. Other system reads
(including ping), record reads and writes retain kernel handling. The context's
`full_status_tool` still names the official tool; the local bootstrap's
`full_status_route` explains that it requires a separate official consumer:
start the installed consumer with `--standby --account <owner> <runtime-config>`
and call `standby_status`. That process verifies its startup selection; status
itself adds no database audit.

Configure each agent's `native-local` MCP command as:

```bash
python3 scripts/native-local-daemon.py stdio \
  --socket /absolute/private/run/standby.sock
```

The server leases one generation. Deltas advance that generation in place, so
its reported age stays close to the refresh cadence. A whole-snapshot fallback
accepts a new generation instead, and until it is activated status reports the
serving generation's actual age. A refresh controller requests that replacement
through a separate owner-only control socket. The relay starts a new network-denied official consumer, waits for
kernel readiness, requires the requested serving generation and a real
`STANDBY_READ_ONLY` write refusal, then swaps readers between requests.
Existing client connections stay open. Failed startup or verification keeps
the old reader serving. Restarting the daemon revalidates and selects a
generation; the relay does not bypass that startup check. Keep
hosted Native as the normal canonical connection. An unavailable relay must
remain unavailable, with no raw database or hosted proxy fallback.

### Running scheduled refresh on Linux

Use the external controller described above with the service templates in
`scripts/systemd/`. The default cadence is one delta tick a minute after the
previous tick finishes, configurable as `cadence_seconds` in
`scheduled-refresh.json`; full copies are at least `full_interval_seconds`
(default six hours) apart, whatever their outcome. There is no catch-up queue or
overlapping attempt. Scheduling is best effort: status reports actual freshness
rather than promising the five-minute RPO.

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
cadence. Enable both services for boot after the first successful activation.
Leave existing agent sessions on the old relay until they reconnect.

Bootstrap and the local `standby_status` return the serving kernel's actual
`freshness.age_seconds`, `serving_head_act`, `serving_materialization` and
`serving_source_history`, alongside advisory `refresh` information including
`last_failed_attempt_at` and the failed phase. That failure timestamp survives
a later successful attempt. Missing or malformed status reports
`status_available: false` while kernel reads and truthful age remain available.
The separate official consumer remains the route for full status disclosure;
use the explicit audit command below for a fresh exhaustive check.

## Auditing the local copy

Deep verification is an explicit audit, never part of a refresh:

```bash
standby_admit --audit /absolute/runtime.json /absolute/installed/mcp-stdio
```

It runs the complete generation verifier (SQLite integrity and foreign keys,
observational conformance, awareness projections) over a consistent private
copy of the current generation and prints `{"generation_id", "passed"}`. A
failed audit leaves the copy serving but marks it `full_refresh_required`, so
the next refresh skips deltas and replaces it with a whole snapshot. Scheduling
the audit is left to the operator.

## Rejected first-release alternatives

- A mutable working copy like the emergency recovery environment: it can fork
  canonical state and cannot provide the Milestone 1 safety claim.
- Copying a live SQLite file or synchronizing SQLite files bidirectionally:
  neither is a transactionally consistent reconciliation protocol.
- Treating R2 operator recovery as ordinary owner refresh: it exposes the wrong
  tenancy and credential boundary.
- Migrating a generation to a new schema in place: it complicates rollback.
  Deltas are not migrations; a schema or DDL change takes a whole snapshot.
- Transparent failover in the first release: it can hide a change in authority
  and freshness from agents.
- Relying on tool discovery or filesystem mode alone: exact dispatch and an
  already-open writable connection remain bypasses.

## Kernel v2 generations (HQ cutover N1)

The standby artifact workflow includes `v2-kernel-probe`; local builds must
name that feature too. Such a node can follow either engine. The authenticated
hosted head identifies the engine; changing from v1 to v2 requests a fresh FULL
snapshot through the existing nonoverlapping refresh controller and cooldown.
It never applies a v2 delta to a v1 generation. A build without
`v2-kernel-probe` still recognizes the v2 head for journal safety, but pauses
refresh before any FULL request and discloses
`engine v2 requires v2-kernel-probe build`. This applies to cold and warm nodes.
At the switch, the newest verified v1 generation is durably pinned outside the
normal current-plus-two retention budget until explicit operator release.
Automatic hot fallback from v2 to v1 is refused.

V2 uses `native.standby-snapshot-manifest.kernel-v2.v1`, the NKV2 file marker,
immutable genesis identity, content/meta sequence heads, act head, blob count,
and the compiled owned schema digest and projection inventory. Imported HQ
keeps the unambiguous source origin recorded in its retained v1 snapshot
provenance; a native v2 workspace derives its origin from its genesis UUID.
The v1 frontier is empty in a v2 manifest and has no v2 continuity meaning.
Catalog engine and file marker must agree. Both reader and refresh writer refuse
an incompatible marker or owned schema; read opens never stamp, repair or migrate.

`native.standby-kernel-v2-delta.v1` is a separate canonical document over whole
acts, transported through the existing authenticated, route/origin-pinned MCP
and chunked HTTP paths. It carries content/meta event tails, their causal
frontiers and only the immutable CAS rows missing from the node's verified
base. The node supplies sorted SHA-256 keys (at most 65,536; an 8 MiB bounded
HTTP start request), never old blob bytes. This covers unbound additions and
bytes used outside attachment-bound events. The receiver checksums only newly
ingested rows. Blob-only deltas are supported without folding when event heads
are unchanged. Oversize new-blob/event transfers use the
existing disclosed FULL fallback and unchanged nonoverlapping six-hour FULL
cooldown; N1 does not bypass or shorten that cooldown. A verified base with
more than 65,536 blobs requests FULL with a disclosed
`kernel_v2_blob_inventory_limit` reason instead of stopping the follower.

The receiver checks available space for two database sizes plus the 256 MiB
delta spool before copying the current database into private staging. If the
reserve is unavailable, it defers with `insufficient_disk`; it does not ask
hosted for a delta or FULL capture, or spend the six-hour FULL cooldown. A
subsequent FULL attempt from an installed v2 base also checks a three-database
reserve plus spool before any hosted capture. Operators can restore headroom
and retry; the verified serving generation remains available meanwhile.

The receiver copies the current database into private staging and opens a writer
only on that scratch file. It checks destination schema, contiguous acts and
sequences, then commits events, causal rows, act head and incremental kernel
projection updates in one scratch transaction. It runs the same replay projectors
on only the new meta events followed by the new content events, and refreshes
search rows for affected records. FULL/repair replay still rebuilds all
projections, reading content in bounded pages. The hosted delta carries a
projection digest over every logical projection table discovered in
`sqlite_master`, excluding only enumerated canonical authority/blob tables
and FTS shadow storage, plus the hosted MCP adapter's durable write receipt
ledger and `kernel_legacy_sql_progress`. The latter is a derived scan cursor:
explicit preparation can advance it outside the event fold, so its position is
not content-equivalence evidence. Legacy SQL header rows in
`kernel_legacy_sql_events` remain covered, together with app custody, installs,
package sources, consent revocations, install outcomes and actions. Schema and
readiness validation and the existing SQL completeness guard still apply to
the cursor; excluding it does not bypass those guards.
The receipt ledger is lazily created with exact compiled DDL and carries no
read projection; v2 shape validation admits it without treating it as event
history. The node computes that same digest after the fold and
requests FULL with `kernel_v2_projection_divergence` if it differs. This is a
full scan on hosted cut and scratch verification, so its wall time still scales
with projection bytes; it does not read canonical event history or blob bytes.
It verifies the resulting coordinates and bytes and
uses normal generation admission, fsync, durable directory publication and atomic
pointer replacement. Existing readers keep their leased prior file throughout;
no replay transaction writes or locks a serving v2 database. Aborted staging work
is never a serving candidate. Derived manifests disclose `materialization: delta`
while their files remain immutable, hash-verified checkpoints.

Delta folding scales with the new events; copying, the full projection digest
and byte/integrity verification still scale with database or projection size.
The closed replay output is moved into staging and then into publication on
the same filesystem, eliminating two redundant database-sized copies. Budget
**about three additional database sizes of transient disk** for FULL and two
for a delta, including staging, the private writer's WAL and publication work,
on top of the current generation, two retained priors and the pinned v1
rollback generation. Allow further space for growth and a bounded 256 MiB
delta spool. Interrupted `kernel-replay-*` directories and
`kernel-delta-*`/`kernel-manifest-*` files are removed on controller startup
under its attempt lock; they never become serving candidates.

Qualification sample (20 October 2026, shared host, dev workspace O0 / dependency
O1): a fresh `v1_import --all --history` from main `e80c486908a3747b0ba89fb6f2124a4a487fad5d`,
merged into the N1 branch, ran on a private snapshot COPY. It emitted
308,335 content events, 8 meta events, 11,681 records and 1,092 blobs
(82,684,130 encoded blob bytes), including 208 app-custody rows and
123,228 legacy SQL headers. Import took 5,147.7 seconds and
returned exit 0 with `capture_complete=true`, zero mismatches, no refusals and
no review entries. Reviewed source accounting explicitly counted 50 deleted
records and one v1-invisible record.

The schema-derived dump covers all 53 included logical projection tables
and 455,320 base rows. The admitted base matched hosted. After a chunked loopback
delta added ten records and one unbound 4 KiB blob, every included table
matched between incremental and hosted, incremental and independent FULL,
and hosted before and after FULL. That FULL repair took
2,421.3 seconds and peaked at 671,736 KiB RSS. The full projection
digest scan took 5.386 seconds; hosted cut and scratch verification each run
one complete scan. The derived SQL scan cursor is excluded as explained above.

The delta took **54.007 seconds end to end**, with 245,644 KiB peak RSS.
Its allocated disk rose from 9,105,215,488 to 12,319,277,056 bytes:
3,214,061,568 transient bytes, about one admitted database size
(3,210,690,560 bytes). Process logical read/write I/O was
50,076,139,443 / 6,802,524,222 bytes; storage-accounted read/write I/O was
0 / 6,339,174,400 bytes, with reads benefiting from page cache. The measured
tree contained the raw source copy, hosted database and one admitted base;
it did not model two retained priors or pinned v1. Initial FULL capture and
admission used 9,632,083,968 additional allocated bytes, about three database
sizes. Retain every generation required by the runbook, plus the conservative
two-database-plus-spool delta reserve or three-database-plus-spool FULL reserve.
The observed delta peak is not a safe capacity floor. These loopback dev
measurements are not a freshness SLA. The temporary copies were deleted
after comparison.

### Disposable VM cache/pressure rehearsal (20 October 2026)

[Sanitized counts and timings](https://github.com/withnative/native-ce/blob/9a01a15d184054da464aa9a93e43e4edc8b7db4d/docs/standby-v2-vm-qualification-2026-10-20.json)
record a separate release-profile rehearsal on this VM. A fresh private v1
snapshot **copy** was imported with `--all --history` at merged N1 `2a410a331`
(4,195.2 seconds; capture complete; zero mismatches, refusals or review entries),
then explicitly prepared and exercised at `6607aa3cf` after merging main.
The base had 308,335 content events, 8 meta events, 11,681 records, 1,092 blobs
and 54 logical projection tables / 455,320 rows. The admitted file was
3,210,711,040 bytes; its full projection digest took 4.256 seconds.

A disposable loopback source process used the real owner head/delta exporters,
spool and ranged transport. A separate harness process ran the production
refresh controller and daemon, publishing immutable generations in `/tmp`.
This is a transport/controller rehearsal, not a full hosted authentication
deployment or a measurement of the installed VM node. The source and current
copy were fsynced and given file-specific `posix_fadvise(DONTNEED)` for cold
runs; system-wide caches were untouched. Each direct delta added ten synthetic
records and one unbound 4 KiB blob. The daemon added another ten records after
its first publication to force a second update.

| Condition | Delta through atomic publication | Peak RSS, MiB |
| --- | ---: | ---: |
| Warm, unconstrained private scope | 46.83 s | 201.7 |
| File-evicted, unconstrained private scope | 50.37 s | 193.6 |
| File-evicted, memory-high 4 GiB / maximum 8 GiB | 67.86 s | 216.0 |

RSS is the whole process run through the subsequent offline-read check; the
controller's high-water marks immediately after delta publication were
153.3 / 153.4 / 154.9 MiB, and the separate source process used
110.0 / 109.9 / 115.1 MiB. File cache is additional: the constrained scope hit
its 4 GiB high watermark and recorded 28,695 high-pressure events, with no OOM.
The 125 GiB VM still had substantial globally available memory; this was a
deliberately constrained private cache budget while other builds/agents ran,
not a claim that the whole VM was memory-starved. The co-located source also
shares this budget; a remote source would not consume the node's local cache.

Controller logical reads were about 45.2 GB per direct delta. Its
storage-accounted reads rose from 0 warm, to 3.21 GB cold, to 14.73 GB under
pressure. These counters exclude the separate source's I/O. Peak additional
allocated disk was about **5.77 GB (1.8 admitted database sizes)**, including
open, unlinked SQLite temporary files in the owned process tree. The earlier
tree-only sample did not count those files. FULL admission used 9.58 GB
additional disk. Keep the conservative two-database-plus-spool delta reserve
and three-database-plus-spool FULL reserve, plus retained generations/growth.

With the normal 60-second tick and unchanged persisted rest, the constrained
daemon published at 75.15 and 237.80 seconds: **162.65 seconds between
publications**. Reported frontier ages at publication were 75.15 and 102.74
seconds; the prior copy reached about 237.80 seconds old before replacement.
No updates overlapped. This two-update observation is not a cadence or
freshness SLA. Unchanged authenticated heads can confirm freshness without a
new file; the measured workload kept changes pending.

During a hosted outage, no new hosted changes reach the copy. Its age keeps
increasing from the last successful authenticated confirmation. Against the
300-second RPO, the observed pre-replacement age would have only about
62 seconds remaining before `beyond_rpo`; immediately after the second
publication it would have about 197 seconds. Inspect actual status instead of
assuming a one-minute-old copy. The live node's configuration and age were
neither inspected nor changed.

The unconstrained cold result is below the older 54-second development-profile
sample; those different profiles do not establish a cache-only speedup.
The constrained result suggests preserving file-cache headroom before a storage
redesign. Reflink was unsupported on this test filesystem. A possible later
optimization is an indexed, all-column comparison for the immutable prefix in
place of `EXCEPT`'s temporary B-tree; it must retain the complete prefix proof
and mutation/refusal tests. No cooldown or verification rule changed here.

**Read qualification gap:** deltas published successfully, but the HQ-sized
ordinary standby `get_record` probe refused with JSON-RPC `-32603` / SQLite
code 9 (`interrupted`). The installed release binary reproduced it; small
fixtures pass. Composed read staging has a two-second deadline. This rehearsal
does not qualify ordinary HQ-sized outage MCP reads or identify the commit
that introduced the scale limitation. Do not bypass its authorization or
deadline checks to claim qualification. The vault's separate unbounded internal
collector result is recorded in [N2 delivery qualification](https://github.com/withnative/native-ce/blob/9a01a15d184054da464aa9a93e43e4edc8b7db4d/docs/v2-continuity-n2-n3.md).
All private snapshot/generation/vault copies and disposable package homes were
deleted after retaining the sanitized evidence.

One attempt lock covers copy through publication; concurrent requests are skipped/coalesced with `refresh_in_progress`
or the normal accepted/coalesced response. After an attempt the node rests for
at least 60 seconds and at least the preceding update's wall time, persisted
across restarts. `kernel_v2_replay_cooldown` is disclosed while waiting; manual
requests cannot bypass this delta rest. FULL capture cooldown semantics are
unchanged. A deliberate deep audit also uses scratch.

Run v2 probes locally with `RUST_MIN_STACK=67108864`, including
`kernel_v2_switch_fetches_fresh_generation_and_retains_v1_for_rollback`.

Outage reads use KernelV2 with physically read-only pools and the same serving
bundle, leases, status and age/RPO disclosures as v1. Bootstrap suppresses run
persistence; an echoed key establishes no new canonical run. These source
changes do not install or qualify a live node or establish a freshness SLA.

Holding v1 journal envelopes is disabled after a validated v2 upstream head.
An actively served v2 copy also disables holding during an outage. The engine
observation persists across restarts, and hold validation/drain consult only
that monitor flag. They issue no compatibility head probes; v1 retains its
existing confirm-down check and drain behavior. Existing pending entries remain on disk, unsent, for
explicit resolution or rollback. `node_status.holding` reports
`kernel_v2_upstream_drain_first`. Drain pending writes before the hosted engine
switch; N1 does not convert or replay journal entries into v2.


### Explicit v2-to-v1 operator recovery

If hosted rolls back to v1, the node refuses the v1 snapshot and stays on its
last v2 copy. Status reports the failed engine transition and the copy's actual
age; it does not declare the v2 copy synchronized with v1. After independently
confirming the hosted v1 rollback, stop the reader and refresh controller using
the installation runbook. With the installed release-stamped binary, run:

```sh
mcp-stdio --standby-release-v1-pin <standby-config.json> --switch-back
```

This verifies the retained v1 generation, atomically selects it, then releases
the pin; restart the reader/controller afterwards. Startup and orphan handoff
respect the selected engine, so retained v2 files cannot undo this explicit
rollback. It never deletes a generation
or replays a v1 journal into v2. To release retention protection without changing
the selected engine after the rollback window ends, omit `--switch-back`.
