/**
 * The index read: its SQL, its ceilings, and the paging that respects them.
 *
 * Lifted out of `store.js` because there are now two callers — the browser,
 * which reads the index directly when the proxy has no snapshot, and
 * `server.mjs`, which reads it to build one. Two copies of this would drift,
 * and the two defects that got through here last time were both in exactly
 * this material: what `lifecycle` is, and which way a cursor pages.
 *
 * Plain ESM with no DOM and no fetch of its own, so Node can import it from
 * `public/` without a build step.
 */

/**
 * `query_sql` caps results at 1,000 rows, and it **caps rather than refuses**.
 * At folder scope nothing came close; at workspace scope the facet read is
 * 11,615 rows and the link read 7,906, so an un-paged select would return a
 * capped answer and every view would be quietly wrong. A page that comes back
 * exactly full means there is more.
 */
export const PAGE = 1000;
/** A stop, so a cursor that fails to advance cannot loop forever. */
export const MAX_PAGES = 60;

export const text = (value) => ({ type: "text", value });

/**
 * The index: every column except `body`.
 *
 * `body` is excluded on purpose and must stay excluded. Two records exceed
 * `query_sql`'s 256 KiB cell ceiling, and the engine refuses the **whole
 * statement** rather than those rows — even `LENGTH(body)` is enough to do it.
 * Bodies come from `get_record`, one at a time, when a tab is opened.
 */
/*
 * Timestamps and local structured queries (app contract v2 R4, plan 5e8560a).
 * `query_sql`'s `records` view renders `updated_at` and `last_activity_at`
 * through `strftime('%Y-%m-%dT%H:%M:%fZ', ...)`, while `query_record` returns
 * and compares the stored text. The two agree exactly when the stored value is
 * already in that millisecond form, as the engine writes it (`now_iso`).
 * So `localQuery.js` answers a time-dependent query (a `*_since` filter, or
 * any order but `name_asc`) only while every held record's timestamps
 * round-trip exactly through `toISOString`; otherwise the engine answers. The
 * rule catches a non-canonical value that reaches the store unrendered (a
 * snapshot or catch-up row); it cannot see one this read has already
 * rendered, and relies on the engine writing only canonical timestamps.
 */
export const COLUMNS = "id, type, kind, name, summary, home_id, lifecycle, maturity, updated_at, last_activity_at, created_at, updated_at_ms, is_current";

export function indexPage(after) {
  return {
    sql: `SELECT ${COLUMNS} FROM records WHERE deleted_at IS NULL AND id > ?1 ORDER BY id LIMIT ${PAGE}`,
    parameters: [text(after ?? "")],
  };
}

export function facetPage(after) {
  return {
    sql: `SELECT record_id, key, value FROM facet_values
          WHERE (record_id > ?1 OR (record_id = ?2 AND key > ?3))
          ORDER BY record_id, key LIMIT ${PAGE}`,
    parameters: [text(after?.[0] ?? ""), text(after?.[0] ?? ""), text(after?.[1] ?? "")],
  };
}

/**
 * Links, with what each one *means* and why it was recorded.
 *
 * `relationship` and `note` used to be dropped here, and a `DISTINCT` on the
 * pair papered over the consequence: two records joined by `part_of` and by
 * `relates_to` collapsed into one nameless edge. That was affordable while
 * every view only asked "is there a link", and stopped being affordable the
 * moment one asked "is this work part of that goal, and why". The note is the
 * sentence somebody wrote on the edge, and on the strategy graph it is the
 * whole content — the nodes are only its index.
 *
 * `DISTINCT` is gone with them, so the cursor has to carry the third column:
 * two rows sharing a pair and differing only in `relationship` straddle a
 * page boundary otherwise, and the second one is skipped silently.
 */
export function linkPage(after) {
  return {
    sql: `SELECT source_id, target_id, relationship, note FROM links
          WHERE (source_id > ?1)
             OR (source_id = ?2 AND target_id > ?3)
             OR (source_id = ?4 AND target_id = ?5 AND relationship > ?6)
          ORDER BY source_id, target_id, relationship LIMIT ${PAGE}`,
    parameters: [
      text(after?.[0] ?? ""),
      text(after?.[0] ?? ""), text(after?.[1] ?? ""),
      text(after?.[0] ?? ""), text(after?.[1] ?? ""), text(after?.[2] ?? ""),
    ],
  };
}

/**
 * The same two reads, narrowed to a set of ids and still paged.
 *
 * Re-reading a set of changed records looks like it needs no paging, and that
 * is the trap: `query_sql` caps at 1,000 rows and caps *rather than refuses*.
 * This workspace averages 3.84 facets per record and one record carries 266,
 * so a chunk of 200 changed records can exceed the cap on its own — and the
 * caller deletes the old rows before re-reading, so a capped answer loses
 * facets permanently rather than visibly.
 *
 * Placeholder order matters: the `IN` list is bound first because it appears
 * first in the statement, then the cursor comparisons.
 */
export function facetPageFor(ids) {
  const holes = ids.map((_, i) => `?${i + 1}`).join(",");
  const c = ids.length;
  return (after) => ({
    sql: `SELECT record_id, key, value FROM facet_values
          WHERE record_id IN (${holes})
            AND (record_id > ?${c + 1} OR (record_id = ?${c + 2} AND key > ?${c + 3}))
          ORDER BY record_id, key LIMIT ${PAGE}`,
    parameters: [...ids.map(text), text(after?.[0] ?? ""), text(after?.[0] ?? ""), text(after?.[1] ?? "")],
  });
}

export function linkPageFor(ids) {
  const holes = ids.map((_, i) => `?${i + 1}`).join(",");
  const c = ids.length;
  return (after) => ({
    sql: `SELECT source_id, target_id, relationship, note FROM links
          WHERE source_id IN (${holes})
            AND ((source_id > ?${c + 1})
              OR (source_id = ?${c + 2} AND target_id > ?${c + 3})
              OR (source_id = ?${c + 4} AND target_id = ?${c + 5} AND relationship > ?${c + 6}))
          ORDER BY source_id, target_id, relationship LIMIT ${PAGE}`,
    parameters: [
      ...ids.map(text),
      text(after?.[0] ?? ""),
      text(after?.[0] ?? ""), text(after?.[1] ?? ""),
      text(after?.[0] ?? ""), text(after?.[1] ?? ""), text(after?.[2] ?? ""),
    ],
  });
}

export const indexCursor = (row) => row.id;
export const facetCursor = (row) => [row.record_id, row.key];
export const linkCursor = (row) => [row.source_id, row.target_id, row.relationship ?? ""];

/**
 * Keyset paging. Not `OFFSET`: the index read is ordered by id, and offset
 * paging over a table being written to skips and repeats rows.
 */
export async function pageAll(call, build, cursorOf, onPage) {
  let cursor = null;
  for (let page = 0; page < MAX_PAGES; page += 1) {
    const { sql, parameters } = build(cursor);
    const rows = (await call("query_sql", { sql, parameters })).rows ?? [];
    if (rows.length > 0) await onPage(rows);
    if (rows.length < PAGE) return;
    const next = cursorOf(rows[rows.length - 1]);
    if (JSON.stringify(next) === JSON.stringify(cursor)) return;
    cursor = next;
  }
  console.warn("query_sql paging hit the safety cap; some rows were not read");
}
