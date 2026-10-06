/**
 * The second Folders package's declared reads (task 79da157).
 *
 * Single source for the exact statements the `agent.folders-browse`
 * install declares. Textually identical (modulo whitespace) to the SQL in
 * the independently authored bundle's install comment
 * (`alpha-tab-proof-packages/folders-browse.html`): a headless leg
 * asserts the normalised equality both ways, so neither side can drift
 * silently. The bundle never sends SQL itself; it reads by need key.
 *
 * browse.roots snapshots at open; browse.children runs on request with a
 * folder id the tab chooses. No clock, no LIKE, no bodies: the chatter
 * exclusion is a type list and the archived exclusion is the engine's own
 * NOT EXISTS spelling over `facet_values`, inside the portable subset.
 */
export const BROWSE_ROOTS_LABEL = "Top-level folders and files you can see (names and positions only, no contents)";
export const BROWSE_ROOTS_SQL = `SELECT id, type, kind, name, home_id, lifecycle, updated_at FROM records WHERE home_id IS NULL AND deleted_at IS NULL AND type NOT IN ('Message', 'Annotation') AND NOT EXISTS (SELECT 1 FROM facet_values WHERE facet_values.record_id = records.id AND facet_values.key = 'archived') ORDER BY name ASC, id ASC LIMIT 200`;

export const BROWSE_CHILDREN_LABEL = "One folder's children you can see (names and positions only, no contents)";
export const BROWSE_CHILDREN_SQL = `SELECT id, type, kind, name, home_id, lifecycle, updated_at FROM records WHERE home_id = ?1 AND deleted_at IS NULL AND type NOT IN ('Message', 'Annotation') AND NOT EXISTS (SELECT 1 FROM facet_values WHERE facet_values.record_id = records.id AND facet_values.key = 'archived') ORDER BY name ASC, id ASC LIMIT 200`;

export function fixtureFoldersBrowseSqlNeeds() {
  return [
    { need: "sql.snapshot.v1", key: "browse.roots",
      label: BROWSE_ROOTS_LABEL, sql: BROWSE_ROOTS_SQL },
    { need: "sql.snapshot.v1", key: "browse.children",
      label: BROWSE_CHILDREN_LABEL, sql: BROWSE_CHILDREN_SQL,
      params: [{ name: "folder", type: "text", max_len: 128 }] },
  ];
}
