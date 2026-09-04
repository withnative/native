# Federated Message content v1

This document records the repository-side amendment to Native records
`2058a99`, `abf4527`, and decision `02b8683`. The relay/cryptographic envelope
remains specified separately in `federation-transport-v1.md`; this is the
decrypted semantic-content contract consumed by the sealed ingest seam in
`src/replication.rs`.

## MessageUnitV1 expectation field

Every `MessageUnitV1` in `native.message.v1` carries a required scalar
`expectation` field alongside its Message semantic content:

```json
{
  "type": "Message",
  "kind": "text",
  "expectation": "reply",
  "prose": "Which option should we choose?"
}
```

The closed v1 vocabulary is:

| Value | Sender declaration |
|---|---|
| `none` | no response is required |
| `ack` | explicit receipt or a substantive reply is required |
| `reply` | a structured reply is required |
| `action` | recipient-owned governed work completion is required |
| `decision` | an authorised governed decision is required |

`expectation` is semantic content, not routing or cryptographic-envelope
metadata. Canonicalization and the source fingerprint cover it exactly as they
cover `kind` and `prose`. The current end-to-end federation client has not
shipped, so this is an in-place completion of the v1 dialect, not a compatibility
alias or version bump. The canonical governed textual payload is
`Message kind:text`; `Message kind:note` is legacy stored data handled only by
the schema-10 migration.

Destination preflight rejects a missing value. An unknown value is an
unsupported required capability and is rejected or quarantined by the adapter;
it is never relabelled. A valid delivery projects `record.created` and the
governed `expectation` facet in one transaction. Exact duplicate delivery
projects neither event again and triggers no reconciliation side effect.

Local supported Message creation has the same requirement through the
`@native/recommended` Message shape and a matching protocol-floor guard. User
and anchored schema rows cannot override the facet on `Message` or
`Message:*`; omission inherits the truthful required, governed declaration.
Historical Messages may lack the facet; absence remains meaningful and is
never backfilled to `none`. Expectation is immutable sender-authored content. A
correction is a new Message linked with `supersedes`.

## Live reconciliation

`native.message.expectation-state.v1(Message, recipient)` is a live derivation,
not a stored status boolean. It returns `unknown`, `not_required`, `open`, or
`satisfied`:

| Declaration | State transition evidence |
|---|---|
| missing | `unknown` |
| `none` | `not_required` |
| `ack` | a recipient-authored `acknowledges` relationship, or a structured recipient reply |
| `reply` | a recipient-authored Message with `reply_to` to the source |
| `action` | a recipient-owned WorkItem `derived_from` the source whose governed lifecycle value is `terminal_positive` |
| `decision` | a recipient-authored governed `Resolution kind:decision` `derived_from` the source |

Evidence requires both recipient authority over the evidence record and a
recipient-authored current relationship assertion. When `owner_id` is present
it is authoritative and must name the recipient; only an absent owner falls
back to the authenticated `record.created` actor. The latest authoritative
`link.added`/`link.removed` event for the live relationship must be a
recipient-authored add. A reply never satisfies `action` or `decision` merely
because prose was sent. Governed lifecycle aliases resolve one hop to the
active canonical value before terminality is judged. `get_record` exposes the
derivation for Message records relative to the authenticated caller; the Rust
API also accepts an explicit recipient identity for inbox and conformance
consumers.

The acknowledgement relationship is an open-additive durable fact under the
existing unique `(source, target, relationship)` link identity. Claim,
liveness, engagement, read/surfacing state, and cross-recipient completion are
separate axes.

## Deliberate v1 limit

Cardinality (`all`, `any-n`, `first`) is deferred. A CE facet is scalar, and
sovereign recipient databases cannot reconcile cross-recipient completion
without an additional distributed protocol.
