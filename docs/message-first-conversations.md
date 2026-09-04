# Message-first Conversations

This document is the repository contract implementing Native decision
`7e8f54f`. A Conversation is thematic classification, not an audience or a
participant roster. There is deliberately no `thread_membership` authority.

## Authority model

A newly authored Message declares, in one atomic creation batch:

- its immutable owner/sender;
- its required governed `expectation`;
- any immutable `reply_to` or `supersedes` links;
- the complete `addressed_to` set, including an explicitly empty set; and
- zero or more initial `participates_in` classifications.

`message.audience.declared` freezes canonical `native-principal` addresses in
the authoritative content log. The `addressed_to` links and
`message_audiences` rows are projections of that event. Generic link mutation
cannot add or remove `addressed_to`, and Message prose, kind, name, owner,
expectation, reply and supersession facts cannot be edited after sealing.

Existing Messages are never guessed. Schema 15 to 16 appends one
`message.audience.legacy_unknown` event per existing Message and projects no
audience rows. Owner, policy, title, filing and old Conversation links are not
treated as recipient evidence. A legacy-unknown Message cannot be canonically
history-shared until a future explicit repair protocol is ratified.

## Conversation classification

`participates_in` is a governed Message-to-Conversation relationship. A
Message can have zero, one or many such links. `manage_messages` supplies
idempotent classify/unclassify operations and an atomic move. The
`message_conversations` projection indexes both directions. Classification
never changes Message policy or audience.

“Unclassified” is a query for readable Messages without a projected
classification. “My Conversations” is derived by joining the caller's readable
Messages through `message_conversations`. Conversation involvement is the
distinct audience of only the Messages that caller can read; responses mark it
`viewer_relative: true` and `roster_authoritative: false`.

## Explicit history sharing

`manage_messages action:share_history` accepts either exact `message_ids` or a
`conversation_id` plus an optional inclusive content-event `snapshot_seq`.
Conversation selection resolves the exact Message IDs inside the write
transaction. The resulting selection identifier is deterministic over actor,
recipient, frontier and sorted IDs, so an identical retry is a no-op and never
becomes an open-ended subscription.

Before the first write the operation verifies `manage` on every Message, a
declared audience on every Message, and canonical local `native-principal` plus
account bindings for the recipient. For every newly shared Message it then:

1. appends `message.shared` with the exact selection, grant and recipient facts;
2. folds an append-only `source:share` row into `message_audiences`; and
3. appends a complete replacement policy event adding that account's `view`
   grant at the Message's own boundary.

The content and policy logs commit together or not at all. Conversation policy
never widens Message access. A local policy can later remove access, but bytes
already exported or delivered elsewhere cannot be recalled.

## Federation/export contract

The initial `native.message.v1` unit must cover sender, exact addressed
principals, reply/supersession facts and semantic payload in its source
fingerprint. A later canonical share is a distinct signed
`native.message.shared.v1` envelope containing:

```json
{
  "type": "native.message.shared.v1",
  "message_id": "canonical-message-id",
  "original_fingerprint": "sha256-hex",
  "grant_id": "stable-grant-id",
  "selection_id": "stable-selection-id",
  "grantor": "network/principal",
  "recipient": "network/principal",
  "snapshot_seq": 1234,
  "shared_at": "RFC3339 timestamp",
  "authority_proof": "transport-defined signed proof"
}
```

The original creation payload and fingerprint do not change. Re-delivery of
the same grant is a no-op; a conflicting original payload for the same Message
identity must be rejected or quarantined. `participates_in` may travel only as
an optional grouping hint and never as access authority. The current transport
verifier remains sealed/private, so schema 17 ships the same-database operation
and this wire contract, not a public unauthenticated federated-share ingest
endpoint.

## Physical projections

- `message_audience_state(message_id)` records `declared`, `legacy_unknown`, or
  the transaction-local `pending_local` creation phase.
- `message_audiences(message_id, principal_id, source, grant_id)` is rebuildable
  from audience/share events and indexes `(principal_id, message_id)`.
- `message_conversations(message_id, conversation_id)` is rebuildable from
  `participates_in` link events and is indexed in both directions.

All three tables are included in content rebuild-and-diff. None is a product
write API and none represents Conversation membership.
