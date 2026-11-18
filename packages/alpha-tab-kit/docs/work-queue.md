# Work queue reference app

A small app for learning what it takes to connect a proposal, a person's
approved brief, an agent session and its returned result. Built from the existing
supplied kit; it introduces no kit API or daemon changes.

Source: [work-queue.html](../examples/work-queue.html). Installation declaration:
[work-queue.declaration.json](../examples/work-queue.declaration.json).

## Try the whole loop locally

From the repository root:

```bash
node packages/alpha-tab-kit/examples/work-queue-fixture.mjs
```

Open `http://127.0.0.1:4319`. Edit the research brief, save it, start the demo
agent, and read the returned result. Send feedback into its conversation.
Reload after typing to try device recovery. The banner always identifies this
as simulated data and simulated agents. Nothing calls hosted Native or a model.
Use `PORT` to choose a different port. Append `?agents=off&state=off` to try a host
without Desktop sessions or device storage.

The fixture injects the real supplied kit and frame bridge. It serves a small
in-memory record backend, a deterministic session service, and the existing
device-state store. It does not prove Desktop admission, real user gestures,
Native write acceptance or actual agent compliance with the return instructions.

## Use it with Native

1. Create a dedicated Native folder and a few `WorkItem/task` records in it.
   Put the suggested brief in each task's `summary`, and evidence with source
   links in its Markdown body. The app reads at most 6,000 evidence characters
   and refuses preparation if that read is shortened or the complete launch
   would exceed Desktop's 12,288-byte app-text budget.
2. Set `DEFAULT_FOLDER` in the HTML to that real folder ID, or enter it under
   **Work folder** in the app. Follow Native's builder guide to create and
   publish the artifact, prepare the installation with the source guard, and
   follow its returned install call. The person previews and adopts it.
3. Agent launch needs Native Desktop, an admitted app with agent access, and
   the create/adopted session features. A narrowed folder grant currently
   prevents launch; choose access through the ordinary Native consent screen.
   The app cannot grant itself more access. Launch permission belongs to the
   host, even though the example only asks for research and a result record.
4. Choose a proposal, edit the brief, choose the machine, provider, model,
   permission mode and agent folder, then **Save approved brief**. Nothing
   launches at this step.
5. Inspect **Exact agent brief and evidence**, then **Start / recover agent**.
   The agent is asked to create a Markdown result linked to this approval.
   Returned records appear without copying a chat transcript. Idle sessions
   are never treated as completed work.

The person's extra edits after approval do not alter a saved request. Save a
new brief to approve them. The app does not mark the source task completed,
send external messages, schedule work, or execute on a timer. The person owns
what happens after reviewing the result.

## Record and recovery contract

- Task: ordinary `WorkItem` with summary and body; no special task ontology.
- Approved brief: `Document/note`, `part_of` the task. Its JSON body records
  `native.work-brief.v1`, exact brief, evidence snapshot, source update time,
  approval time, choices and a permanent random `requestKey`. Approval is
  ordinary authored record content, not an engine-enforced permission token.
- Result: `Document/note`, `part_of` the approved brief and `relates_to` the
  task. The prompt requests `idempotency_key: result-<requestKey>` on create
  and guarded edits to the existing result for follow-ups. The host does not
  enforce agent obedience to this convention.
- Reads: bounded folder list (30 tasks initially, kit paging up to 200),
  one selected task, latest five linked approvals and latest five results,
  each linked body capped at 24,000 characters. Longer result previews link
  to the full record. These joins use `useQueryFeed`; standard task reads use
  `useRecord` / `useRecordList`. No workspace-wide scan.
- The selected proposal/folder, displayed brief (including an unedited suggestion),
  edited-vs-suggested flag, and a session hint use `createAppState` on this device, debounced
  by 200 ms. Only acknowledged saves say **saved on this device**; an absent
  store keeps editing usable and says **this page**. Closing before that
  acknowledgement may lose the last typing. Device state is not cross-device
  sync. Source updates do not replace edited text.
- Approved briefs/results survive independently in Native. After a lost
  launch answer or reload, **Check existing conversation** calls
  `createStatus` with the canonical key. Starting again uses exactly that
  key and request; Desktop owns deduplication. Reload never launches work.
- `promptFor` implements the v1 return protocol. Preserve its v1 byte output
  when updating the app; introduce a new brief schema for a changed prompt.
  Changing text under the same request key can produce a mismatch refusal.
- Scope changes retire the device store, clear the displayed work and require
  reload. They never replay writes under another account.

## What was awkward while building it

These are observations and possible next improvements, not new supported APIs.

1. **Saving and starting need separate gestures.** Saving approval is async;
   a Desktop launch needs a fresh click. The two-step UI works, but a recipe
   should make this sequencing obvious to authors.
2. **The session helper cannot restore a permanent launch key.** Its create
   helper owns its key and omits export/restore. For this app, the canonical
   approval must already own the key before launch. The example composes
   `useWrite` with the existing `native.agentSessions.create` API, preserves
   that request ID, and translates its result. It uses `useAgentSessions`
   for the catalog, list, open, status lookup and subsequent sends. A small
   supported keyed-start recipe would remove this extra adapter.
3. **No built-in source/return association.** The app writes a return protocol
   into the prompt and queries result links itself. It can recover by request
   key, but has no platform-enforced record-to-session binding. The instructions
   are a convention; a real agent trial is needed to measure reliability.
4. **Record hooks do not cover linked result sets.** Two small SQL joins remain
   for approvals and results. A link-aware read recipe could remove them
   without prescribing domain-specific fields.
5. **State composition is manual.** The app connects per-record draft state,
   save acknowledgement, scope disposal and session hints itself. The core
   already has the underlying facilities; a composed example is more useful
   here than another storage transport.
6. **Catalog choice UI and launch budgets remain app code.** Selecting host,
   provider, model, mode and folder, validating the total UTF-8 brief budget,
   and keeping those choices stable all take code beyond a create call.

The next learning step is to run a small real research task in Native Desktop
and observe whether the agent returns a correctly linked result and edits it
on feedback. Fixture success alone does not establish that.

## Verification

```bash
node --test packages/alpha-tab-kit/test/work-queue-example.test.mjs
```

The browser tests use the real bridge and supplied kit. They check exact
approval versus later draft edits, no launch on save/reload, linked results,
follow-up targeting, lost-answer recovery, typing preserved through source
updates and reload, host capabilities, refusal, and scope disposal. Playwright
is optional as in the other kit browser tests; browser cases report skips
when it is absent. `ALPHA_TAB_KIT_PLAYWRIGHT` may name an existing project
with Playwright installed.

## First live trial: empty launch choices

Richard reported all four launch dropdowns empty and greyed out in adopted
0.1.1. The app gated catalog loading on session-list readiness, filtered
catalog hosts through the session list, and silently discarded catalog
failures. Fixture regressions reproduce both an unavailable conversation list
and a list with no hosts despite a valid catalog.

0.1.2 reads launch choices independently, retains previously delivered choices
during a transient read failure, retries transient catalog failures twice,
and offers **Reload agent choices** with visible loading/refusal/unavailable
feedback. The picker and its pre-dispatch check use the catalog's host/epoch;
Desktop still validates the actual launch. Tests cover unavailable/empty
session lists and recovery after catalog failures while retaining typed text.
The conversation was not bound to a Desktop observation host, so the precise
reason the first live catalog/list failed was not directly observable.

## Second live trial: blank proposal/brief on reopen

Richard's screenshot of 0.1.2 showed no proposal list and “Select a proposal”
while the footer said drafts were restored. The app saved neither selection
nor an unedited suggestion, waited for folder-list delivery before mounting
`useRecord`, and reported restoration even for an empty device store.

0.1.3 restores the selected ID and its form draft independently of list reads.
It saves the initially displayed suggestion too, with `edited: false`; fresh
canonical suggestions update it until the person edits. While task reads wait,
the saved text remains visible/editable. Approval still needs the source read.
A cold start with no saved brief shows Loading proposals, not an empty-choice
prompt or a false restoration claim. Actual Native records and evidence stay
with kit/host record caching; this is form/navigation state, not a second
record database. This app fix does not prove why the live host's warmed list
read was delayed. Once 0.1.3 has loaded and acknowledged its device save, reopen
can restore the form even with both list and task responses held. Browser
regressions exercise that case and preserve typing when fresh data arrives.


## Source integration — plan 4cac716, Delivery A

Codex integrated the original Work queue author's retained 0.1.3 example,
fixture and tests into the main source lane. Read notices now name the source
task, saved-brief list or returned-result list, distinguish load from refresh,
and provide one retry action. An acknowledged new approval remains available
when the independent linked-brief list fails. A synchronous edit guard prevents
an earlier suggested-brief effect from overwriting typing during startup.
Frozen approval snapshots, the v1 launch prompt and stable launch/recovery keys
remain unchanged. No installed artifact update or actual agent launch is part
of this source increment. Fixture tests do not establish installed Desktop or
node behavior.
