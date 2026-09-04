# `whats_changed`

`whats_changed` is a read-only, stateless, authorization-filtered traversal over
the authoritative `content_events` log. It answers “what changed after local
replay position N that this caller may see?” without storing a server-side
acknowledgement cursor.

## Request

```json
{
  "after_local_seq": 120,
  "through_local_seq": 240,
  "limit": 200,
  "scope_record_id": "record-id",
  "actor_scope": "all",
  "accounts": ["account-token"],
  "for_run": "scout-chair-a748b2",
  "include_child_runs": false,
  "event_families": ["updated", "moved"],
  "order": "oldest_first"
}
```

- `order` is `oldest_first` (default) or `newest_first`. It chooses the
  traversal direction only; every filter, the pinned high water, and the page
  contract are identical in both directions.
- `after_local_seq` is the exclusive keyset cursor in traversal order — "strictly
  after this position in the direction being read". Reading `oldest_first` it
  is a lower bound (`after_local_seq < local_seq <= high_water_local_seq`) and
  defaults to `0`. Reading `newest_first` it is an upper bound
  (`local_seq < after_local_seq`, still `local_seq <= high_water_local_seq`) and
  defaults to just above the log, so the first
  page starts at the newest visible change. A `newest_first` cursor above the
  pin is clamped to `high_water_local_seq + 1` rather than rejected, because opening
  above the pin is the normal case; an `oldest_first` cursor above the pin
  remains an error. A negative `after_local_seq` is an error in both directions.
  There is no separate `before_local_seq`: one cursor name is what lets
  `next_request` round-trip verbatim.
- Omit `through_local_seq` on the first call. The response pins the current
  event-log maximum as `high_water_local_seq`; subsequent pages must keep that
  value.
- `limit` is the maximum number of caller-visible events returned after
  authorization and all supplied filters. It defaults to `200`, must be
  positive, and cannot exceed `1000`.
- `scope_record_id` selects the root's current live, visible, unarchived
  subtree. It deliberately does not reconstruct former descendants.
- `actor_scope` is `all` (default), `self`, or `others`. `others` includes
  legacy events with no actor. `accounts` is an exact filter over portable,
  non-null actor tokens.
- `for_run` selects one complete run key. `include_child_runs: true` includes
  recursively asserted descendants and is invalid without `for_run`.
- `event_families` accepts `created`, `updated`, `moved`, `facets`, `impacts`,
  `links`, `annotations`, and `deleted`. `impacts` selects ordinary events whose
  event-time identity is `Outcome kind:impact`; it does not infer impact from
  unrelated work-item changes or use the record's present-day kind.

All supplied filters compose with AND. Empty `accounts` and `event_families`
arrays are errors. Duplicate array values are accepted and normalized away;
unknown families are errors.

## Stable authorization-filtered paging

The first call pins the high water and reads scope/run membership in one read
snapshot. The server then walks the pinned window in bounded raw chunks —
`after_local_seq < local_seq <= high_water_local_seq` ascending, or
`local_seq < after_local_seq` descending
within the same pin — applying record authorization and every supplied filter
before an event can occupy the page. It continues until it has at most `limit`
visible events plus a visible look-ahead, or exhausts the pinned window.
Hidden-only or filter-rejected events therefore cannot shrink a visible page
and cannot set `has_more`; `has_more` means at least one more caller-visible
matching event.

`scanned_through_local_seq` is the traversal cursor, so it ascends towards
`high_water_local_seq` when reading oldest-first and descends towards `0` when
reading newest-first; an exhausted window lands it at that far end. The echoed
`after_local_seq` is the effective cursor actually used, so a clamped
`newest_first` opening cursor is reported as `high_water_local_seq + 1`.

The database-local replay cursors (`after_local_seq`,
`scanned_through_local_seq`, and `next_after_local_seq`) and
`high_water_local_seq` are scoped to the response's `local_database_id`. They
can advance across hidden positions, but disclose no event content, record ID,
raw-row count, or grouping information. They are not portable event identity,
causal order, or conflict priority. Validation of a future high water is generic
and does not echo the current maximum.

New events committed after the first page do not enter the pinned traversal.
To change filters, start a new traversal from an explicitly chosen cursor.

When `has_more` is true, pass `next_request` back verbatim. It contains the
advanced `after_local_seq`, pinned `through_local_seq`, materialized defaults, preserved
filters, and deterministically de-duplicated arrays. `order` is carried only
when it is not the default, so an oldest-first continuation stays byte-identical
to the one callers already round-trip. It is null when the window is exhausted.
This object is derived from the request and response; the server stores no
progress state.

## Response

```json
{
  "local_database_id": "db-example",
  "after_local_seq": 120,
  "scanned_through_local_seq": 200,
  "high_water_local_seq": 240,
  "next_after_local_seq": 200,
  "has_more": true,
  "scanned_event_count": 3,
  "matched_event_count": 3,
  "changes": [
    {
      "record_id": "record-id",
      "record_name": "Current label",
      "record_type": "Document",
      "actor": "account-token",
      "actor_name": "Current display name",
      "run_key": "scout-chair-a748b2",
      "first_local_seq": 125,
      "last_local_seq": 180,
      "first_event_at": "2026-08-02T08:00:00.000Z",
      "last_event_at": "2026-08-02T08:10:00.000Z",
      "event_count": 3,
      "event_types": ["record.updated"],
      "event_families": ["moved", "updated"],
      "changed_fields": ["home_id", "summary"]
    }
  ],
  "next_request": {
    "after_local_seq": 200,
    "through_local_seq": 240,
    "limit": 200,
    "actor_scope": "all",
    "include_child_runs": false
  }
}
```

Matching events are grouped within a page by
`(record_id, actor, run_key)`. Both `scanned_event_count` (retained for wire
compatibility) and `matched_event_count` count only caller-visible events in the
page, after all filters; neither reports how many raw rows the engine examined.
Reading oldest-first, groups are ordered by their first visible sequence
ascending; reading newest-first, by their last visible sequence descending,
so a record touched both long ago and just now sorts on its recent activity.
`(record_id, actor, run_key)` ties break on the group key in both directions.
`first_local_seq`/`last_local_seq` and `first_event_at`/`last_event_at` are the minimum and
maximum over the group's visible events regardless of traversal direction.
Page boundaries may split and repeat a group; `first_local_seq`, `last_local_seq`, and
`event_count` preserve its visible event provenance. Current record and actor
labels are convenience metadata: deleted or missing records have null labels,
and an actor whose display-name lookup fails falls back to its opaque token.

Family mapping is total — over every event type, not merely the canonical set:

| Event type | Families |
|---|---|
| `record.created` | `created` |
| `record.updated` | `updated`, plus `moved` when `home_id` is present |
| `record.deleted` | `deleted` |
| `record.type_corrected.v1` | `updated` |
| `facet.set`, `facet.unset` | `facets` |
| `link.added`, `link.removed` | `links` |
| `annotation.target.set`, `annotation.target.removed` | `annotations` |
| `message.reaction.added.v1`, `message.reaction.removed.v1` | `annotations` |
| `artifact.source_attested`, `unit.created.v1`, `unit.revision.recorded.v1`, `occurrence.bound.v1` | `updated` |
| any other content event type | `updated` |

The rows above `any other` are classified deliberately; the last row is the
default for everything else. A content event type this aggregate has no specific
opinion on is summarized as `updated` — something happened to this record — and
its exact type is still listed in `event_types`. The canonical set grows
independently of this mapping, so an event type is never a reason for the call
to fail. An unfamiliar type makes a group's family slightly vaguer; it does not
empty the family set, does not remove the group from an `updated` filter, and
does not take the response down with it.

Every row in the table also contributes `impacts` when the event-time record
identity is `Outcome kind:impact`. This includes creation, corrections to the
atomic `impact` facet, lifecycle/maturity/facet changes, links authored on the
impact, and deletion. A kind-changing event is classified using the identity
after that event is applied. Because identity is reconstructed from the pinned
event prefix, later kind changes cannot rewrite historical family membership.

`changed_fields` contains recognized record projection keys for create/update
events, `facet:<key>` for facet events, and no synthetic field names for link,
annotation, or deletion events. Payload metadata such as `reason` is excluded.
