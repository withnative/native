# Temporal structured reads

`get_record`, `query_record`, and `get_structure` accept an optional `as_of`
selector:

```json
{ "as_of": { "content_seq": 412 } }
```

or:

```json
{ "as_of": { "timestamp": "2026-08-02T09:30:00Z" } }
```

Exactly one arm is required. Sequence zero is the empty content projection;
future sequences are rejected. A timestamp resolves to the greatest event
sequence at or before it, with the highest sequence breaking equal-timestamp
ties. Timestamps before the log resolve to zero and timestamps after it resolve
to the observed head.

Every explicit historical response echoes `as_of`, `resolved_content_seq`, and
`content_head_seq`. Even a selector that resolves to the current head is
replayed. Omitting `as_of` keeps the ordinary live fast path.

`query_record.activity` is the deliberate exception to caller-selected
top-level `as_of`: its first page pins `activity.through_seq` to the content
head and uses that same sequence as `subject_as_of_seq`. A top-level `as_of`
cannot be combined with `activity`. See [`activity-query.md`](activity-query.md).
The pin fixes its content-defined event prefix and membership, but each page
still reapplies current authorization and live schema/vocabulary governance;
those live tiers can change which results are visible or how transitions are
interpreted.

`resolved_content_seq` and the global `content_head_seq` are an explicit,
intentional authorization exception: they are public synchronization metadata,
not evidence that the caller can view any event or record at those sequence
positions. Record contents, result occupancy, counts, and traversal structure
remain caller-authorized. This mirrors the cursor/high-water contract used by
`whats_changed`.

The historical boundary is intentionally mixed-tier and explicit:

- records, links, facets, annotation targets, and projection-maintained indexes
  come from the replayed content prefix;
- schema, vocabulary, and governed-kind interpretation are live;
- retained content-addressed blob bytes are live, with unavailable bytes
  reported as unavailable rather than inferred from the replay scratch store;
- operational jobs and historical metadata are not available through this
  lens.

One batch `get_record` call replays once and serves every requested ID from that
same projection. Saved View resolution uses that same historical content lens.
`search` and `query_sql` do not accept `as_of`.

## Field-level blame recipe

Read the record's newest events first and inspect changed payload fields:

```json
{
  "record_id": "record-id",
  "order": "newest_first",
  "limit": 100
}
```

If the setter is not present, pass `next_after_seq` back as `after_seq`. The
cursor is gap-free in either order. This is field-level event inspection, not
span-level body blame.

## Structured-query bisect recipe

For a predicate expressible by `query_record`, binary-search content sequences
client-side. Call the same structured query with
`as_of:{"content_seq":N}` at each midpoint. If the goal is the first sequence
where the predicate flips, the caller must establish that the predicate is
monotone over the searched range. No server-side bisect tool is provided.

Overlay, span blame, historical SQL/search, replay caching, and historical meta
replay are deferred.
