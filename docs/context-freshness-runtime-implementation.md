# Receipt runtime implementation note

Schema 29 implements the candidate receipt-driven freshness contract on the
existing record and event substrate. It does not introduce a second content
authority: Unit envelopes remain records, exact idea bytes remain
`unit.revision.recorded.v1` events, and dependency, assessment, Receipt,
reconciliation, supersession, and audit state is projected from
`content_events`.

The implementation deliberately revises the original candidate in these ways:

- the v1 semantic kernel stays small—Unit, exact revision, Occurrence,
  Dependency, and Receipt—while assessment, reconciliation, uncertainty, and
  supersession are event-backed evidence or relations rather than new record
  identities;
- a durable output and all of its evidence are one aggregate
  `receipt.committed.v1` event. The Receipt is itself the output body revision
  and therefore the only live, replay, history, and cursor visibility boundary;
- exact dependency impact is active only for the consumer's current body
  revision, while historical Receipt explanation remains receipt-scoped;
- reconciliation evidence may be embedded atomically in a replacement Receipt;
  later independent reconciliation remains a closed
  `reconciliation.recorded.v1` command;
- conflicting reconciliation evidence is retained and derived as unresolved;
- materiality, execution, and disclosure are separate derived decisions, and
  hard-stop categories do not rewrite the materiality verdict;
- uncertainty is explicit lineage over exact references, reauthorized at each
  read, and cannot disappear merely because a downstream output was written;
- authorization-redacted debt is sealed as one opaque `withheld_context` bit,
  never as an empty/fresh result. It propagates through later consumer Receipts
  and downstream Receipt-output sources without exposing identities or counts;
- Unit supersession is plural, authorization-aware, bounded, and resolves
  terminal Units to their exact heads at the read high-water;
- dependency audits can describe both declared dependencies and observed
  omissions.

The runtime is intentionally internal: no new MCP tools or public compatibility
promise are introduced. Its payloads pin both
`native.freshness-kernel.v1` and `native.receipt-runtime.v1`. Schema 28's
historical fixture and fingerprint remain unchanged; schema 29 has its own
forward migration, frozen DDL fingerprint, generated SQL guide, rebuild
contract, and conformance coverage.

The candidate runtime is implemented on the SQLite event projector. Postgres
canonical import remains deliberately fail-closed for the v29 aggregate
Receipt event until an equivalent projector exists; it must not partially
materialize Receipt-authored bodies.
