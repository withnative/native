# Composable activity queries

Direct `query_record` calls can terminate the existing filter/traverse pipeline
as canonical activity instead of records. The pipeline always supplies its
complete caller-authorized record set; record ordering, facet ordering, record
`limit`/`offset`, `count_by`, and `aggregate` are mutually exclusive with the
`activity` terminal.

```json
{
  "steps": [
    { "step": "filter", "ids": ["epic-id"] },
    {
      "step": "traverse",
      "target": "links",
      "relationship": "part_of",
      "direction": "in"
    }
  ],
  "activity": {
    "after_local_seq": 120,
    "through_local_seq": 240,
    "actors": { "accounts": ["account-token"] },
    "actions": {
      "any": [
        {
          "kind": "field_transition",
          "field": "lifecycle",
          "to_terminality": "terminal_positive"
        },
        {
          "kind": "link_change",
          "change": "added",
          "relationship": "supersedes",
          "direction": "out"
        }
      ]
    },
    "limit": 200
  }
}
```

Omit `through_local_seq` on the first request. The engine pins the current
database-local content head, replays the content projection to that position,
and evaluates the full
subject pipeline through that historical `ReadLens`. The response echoes both
`local_database_id`, `high_water_local_seq`, and `subject_as_of_local_seq`.
Pass `next_request` back verbatim for the next page: it retains the original
steps and pinned `through_local_seq` while advancing only
`activity.after_local_seq`. Content writes after the pin cannot alter
the selected event prefix or content-defined subject membership. Every page
reapplies current authorization plus live schema and vocabulary governance, so
access revocation or governance edits can change visible or interpreted results.

## Typed action clauses

`actions.any` is a non-empty shallow OR. Populated constraints inside one clause
are ANDed:

- `event`: any exact `event_types` and/or `event_families`, plus
  `changed_fields_any` and `changed_fields_all`.
- `field_transition`: one spine `field`, with optional exact `from`, exact `to`,
  and live governed `to_terminality`. JSON `null` explicitly means absence, so
  creation can be selected as a transition from absence.
- `facet_transition`: one facet `key`, with the same optional transition
  constraints. Observation-only facet events do not mutate or match the
  current-state transition stream.
- `link_change`: optional `change` (`added` or `removed`), exact
  `relationship`, and `direction` (`out`, `in`, or `both`) relative to the
  selected subject set.

The engine folds the pinned content prefix once to derive event-local
before/after state. Natural-language actions such as “shipped” remain an agent
or application compilation concern; v1 has no opaque action strings, nesting,
negation, saved named actions, ranking, coalescing, or summarization.

## Result and authorization

```json
{
  "shape": "activity",
  "activities": [
    {
      "event": {
        "local_seq": 173,
        "id": "event-id",
        "record_id": "task-id",
        "type": "record.updated",
        "payload": { "lifecycle": "completed" },
        "actor": "account-token",
        "run_key": null,
        "parent_key": null,
        "intent": null,
        "created_at": "2026-08-04T09:00:00.000Z"
      },
      "matches": [
        {
          "clause": 0,
          "kind": "field_transition",
          "field": "lifecycle",
          "before": "active",
          "after": "completed",
          "before_terminality": "open",
          "after_terminality": "terminal_positive"
        }
      ]
    }
  ],
  "matched_event_count": 1,
  "local_database_id": "db-example",
  "high_water_local_seq": 240,
  "subject_as_of_local_seq": 240,
  "has_more": false,
  "next_request": null
}
```

One canonical event occupies one page slot even when several clauses match;
`matches` then contains every matching clause. `limit` and
`matched_event_count` count authorized matching events, not clauses or groups.
Record authorization, event-record authorization, actor redaction, embedded
record-reference redaction, and action filtering all happen before an event can
affect page occupancy or `has_more`.

Every `*_local_seq` in the request and response is scoped to
`local_database_id`. It is a database-local replay position, not portable event
identity, causal order, or conflict priority.

`whats_changed` remains the backward-compatible coalesced mechanical-change
surface. Saved `Collection kind:query` envelopes remain record-producing at
`v: "0.2"`; their validation rejects activity, count, and aggregate terminals.
