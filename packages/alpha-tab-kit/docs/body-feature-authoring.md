# Body feature author preparation

`planBodyFeatureInstall` is a Node-only opt-in authoring API. It accepts the
closed `records.body.read.v1` descriptor with
`scope: 'viewer-visible-current-bodies'`, validates the frozen structural
baseline, and returns an immutable `alpha-tab.body-feature-plan.v1`.
It does not execute HTTP, carry cookies or grant authority. Generic
`parseDeclaration`, `planInstall`, `runInstall` and fake hosting refuse this
feature; `runInstall` refuses before options, steps or client access.

Feature staging retains the qualified chunked note/append/source-event/re-kind
route. It does not inherit the ordinary installer's whole-body default, icon
facets, `chunked` or `afterRemovalEventId` options. Explicit replacement remains
an original remove step and removed-generation placeholder. Keep the original
plan and its idempotency key for explicit same-intent retry; constructing another
plan creates another intent. Source writes and a plan are not adoption proof.

A separately qualified, selected-database Cookie host executor must resolve the
original source placeholders and submit the bounded original request to
`POST /databases/{db_id}/alpha-tabs/body-feature`. The browser manager intake is
not supplied here. Do not import this Node module into browser UI, send it through
CLI/Bearer/MCP, or execute its sourceSteps with a generic browser ToolStep runner.

Mixed SQL/effect/session declarations are retained in full, but this host handoff
states body-only availability. Other reads, effects and sessions are withheld.
Dormant ordinary BodySet object authoring remains separate and is refused by the
frozen feature grammar and extended canonical commitment path. Historical bare
unknown names remain inert strings there; ordinary BodySet parsing retains its
recognized bare-name refusal. No Save, default app, reads.v1 or session activation
is added.

Standalone canonical digests support the inert body descriptor and qualified
baseline sessions. Session absence emits no field; explicit empty sessions and
duplicates are commitment material. Malformed sessions fail closed. Earlier kit
session-bearing digests omitted this material and were wrong; this correction
uses fixed qualified Rust commitments without changing engine history or the
digest version. Session-only digest support does not imply install support.

Ordinary descriptor/session-absent digests, dormant BodySet digests, plain X.Y.Z
versions, icons, default whole-body installs and CLI/remote behavior are retained.
The body wire/controller/assembler source and typed subpaths are preparation
only. Production bootstrap/hash/runtime composition, browser manager and public
UI offering require separate review and qualification.
