# Saved-session sharing wire fixture

Generated from the actual JavaScript request planner by:

```sh
node experiments/alpha-tab-proof-packages/saved-session-sharing-fixture.mjs
```

The adjacent JavaScript unit test compares the fixture with the current planner.
`tests/tools/saved_session_sharing_tools.rs` exercises these requests against the
real SQLite engine and authenticated fixture accounts. Its owner placeholder is
replaced with the disposable fixture owner, including inside frozen event bodies.
The fixture also includes the controller's exact authenticated-owner and private
intent-scan queries. The engine regression executes them, covering the portable
numbered-placeholder contract and keeping owner checks in hydrated record reads
rather than selecting the non-public `owner_id` SQL field.

The proof covers a refused event guard rolling back a folder move, inherited
access becoming visible and then revoked, the owner floor and explicit audience
exceptions, a superseded competing Share, and replay of an old Stop receipt after
same-channel re-sharing. It sends no real messages and activates no service.
It does not prove the app's pending-intent scan, UI, adoption or live-cache behavior.

`history-capture.json` contains actual public `query_sql`, `get_history` and
selected `get_record` response fields captured from the same disposable SQLite
fixture using the production registry and authenticated `acct:alice`. The
capture used `get_history {record_id, order:"oldest_first", detail:"full",
limit:1000}` before the first access change. The account and all records are
synthetic. Event ids, database id, owner id and timestamps are retained from
that run; they are evidence of the wire format, not expected stable identities.

The JavaScript history tests consume these responses directly. In particular,
ordinary CREATE has `owner_id:null`, facet history values are strings (including
numeric versions), and record facets are an array of key/value rows. Recovery
must verify the CREATE actor against `current_principal()` and reconstruct the
original owner intent, rather than trusting mutable current card fields.
