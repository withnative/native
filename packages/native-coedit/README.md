# @withnative/native-coedit

Transport-agnostic live co-editing client for `session.body.v1`.

Shared state per record is one Yjs doc with a single root `Y.Text` named
`body` holding Markdown; the wire format is Yjs update encoding v1.

## Status: Unit B (CoeditClient + FakeHome)

- `src/offsets.ts` — UTF-8 byte ⇄ UTF-16 index helpers.
- `src/client.ts` — `CoeditClient`: confirmed + pending layers, leased-id authoring,
  refusal rebuild with recovery draft, item-identity delete replay, idempotent
  duplicate refusals, blocked-on-lease-exhaustion
  (`refused` / `rebuilt` / `exhausted` / `blocked` events).
- `src/testing/fakeHome.ts` (exported as `./testing`) — in-process home double.
- `NOTES-rebuild.md` — the rebuild rule, coverage check, and known limitations.

**Lifecycle.** `open()` is single-use (repeat calls are ignored; the transport has no
unsubscribe), and a delayed `session.opened` after close is ignored. Wait for the `live`
status before editing: edits before it are never sent; at `session.opened` their **net
plaintext** is re-authored under the leased id, inserted at the start of the body. A pre-live
type-then-delete therefore sends nothing and cannot resurrect text. `confirmed` is private; edit
and observe through `text`/`visible`. Wrong-session, duplicate-`opened` and post-close frames
are ignored. `close()` (or a server `session.closed`) surfaces every unconfirmed edit as
`closed.draft` before clearing pending; it is idempotent and also sends `session.close` from
a `blocked` session. **The app must disable editing while `status === "blocked"`**: such
edits are not sent, and are preserved in `closed.draft` only.

The ProseMirror binding is explicitly out of scope (next increment).

## Bounded core pool compatibility

The in-process Rust core issues each admitted Edit or View peer three unique,
monotonically retired IDs, ordered `[initial author, spare rebuild author,
reserved confirmed]`. Three is the provisional minimum useful for one genuine
refusal rebuild with this SDK: the first refusal can use the spare and replay
independent survivors; the second blocks with visible state equal to confirmed,
surfacing all unconfirmed insert/delete intent for recovery. Duplicate or stale
refusals do not consume the spare. The confirmed doc does not author; the former
singleton defect was the lack of a spare on the first refusal.

This ordering/count is an engineering convention, not a normative contract
number or M8a durable device lease implementation. View leases confer no Edit
authority. Caps remain 16 Edit and 32 View peers: 144 IDs per fully seated record,
roughly 14.9 million such records in the low-half lease range. High-half seeds
remain separate; leaving never recycles a pool within the registry lifetime.
FakeHome's explicit `leasePoolSize: 3` tests and the separate Rust tests establish
bounded pool coherence, not Rust-to-SDK wire interoperability. Persistence,
lease refresh, durable identity, transport/broker and refusal-frame translation
remain separate integration work.

## Opt-in actual Rust core interoperability

`npm run test:core-interop` consumes a separately built, source-hashed
`coedit-core-fixture` executable through the real `CoeditClient` transport.
`COEDIT_CORE_FIXTURE_BIN` must name its absolute path; missing/stale binaries fail,
never skip. Ordinary `npm test` remains limited to `test/**/*.test.ts`; typecheck
also covers `interop/`. This suite is independent of the FakeHome tests and is
not enabled in CI by this unit. See
[the fixture README](../../crates/coedit-core-fixture/README.md) for exact bounded
build/test commands, source binding, fixture-only framing and limitations.
Successful execution would prove this test path's core/SDK byte compatibility,
not production authority, durable leases, version cuts or contract readiness.
