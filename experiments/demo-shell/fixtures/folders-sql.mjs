/**
 * The Folders package's declared reads (task 79da157, slice 1).
 *
 * Single source for the exact statements: the package (`folders.html`)
 * carries copies it cannot import (no external scripts in the bundle),
 * and the fixture serves them from here. A headless leg asserts the copies
 * are identical, so neither side can drift silently.
 *
 * Slice 1 is roots + one folder's children + one record by id (ancestry
 * walks call by-id once per level, cycle-guarded, in the tab). No clock,
 * no LIKE, no bodies: the chatter exclusion is a type list and the
 * archived exclusion is the engine's own NOT EXISTS spelling over
 * `facet_values` (the `NOT_ARCHIVED` form `store.js` cites), so the
 * statements stay inside the portable function subset main's SQL
 * validator admits for declared needs.
 *
 * The tab filters nothing itself: kids() semantics (no Message/Annotation,
 * no archived facet) are answered host-side, so the frame renders what
 * the viewer may see without a second client-side allow-list.
 */
export const FOLDERS_ROOTS_LABEL = "Top-level folders you can see, by name";
export const FOLDERS_ROOTS_SQL = `SELECT id, type, kind, name, home_id, lifecycle, updated_at, updated_at_ms FROM records WHERE home_id IS NULL AND deleted_at IS NULL AND type NOT IN ('Message', 'Annotation') AND NOT EXISTS (SELECT 1 FROM facet_values fv WHERE fv.record_id = records.id AND fv.key = 'archived') ORDER BY name ASC, id ASC LIMIT 200`;

export const FOLDERS_CHILDREN_LABEL = "One folder's contents, by name (first 200)";
export const FOLDERS_CHILDREN_SQL = `SELECT id, type, kind, name, home_id, lifecycle, updated_at, updated_at_ms FROM records WHERE home_id = ?1 AND deleted_at IS NULL AND type NOT IN ('Message', 'Annotation') AND NOT EXISTS (SELECT 1 FROM facet_values fv WHERE fv.record_id = records.id AND fv.key = 'archived') ORDER BY name ASC, id ASC LIMIT 200`;

export const FOLDERS_BY_ID_LABEL = "One record's folder position, by id";
export const FOLDERS_BY_ID_SQL = `SELECT id, type, kind, name, home_id, lifecycle, updated_at, updated_at_ms FROM records WHERE id = ?1 AND deleted_at IS NULL`;

export function fixtureFoldersSqlNeeds() {
  return [
    { need: "sql.snapshot.v1", key: "folders.roots",
      label: FOLDERS_ROOTS_LABEL, sql: FOLDERS_ROOTS_SQL },
    { need: "sql.snapshot.v1", key: "folders.children",
      label: FOLDERS_CHILDREN_LABEL, sql: FOLDERS_CHILDREN_SQL,
      params: [{ name: "folder_id", type: "text", max_len: 128 }] },
    { need: "sql.snapshot.v1", key: "folders.by_id",
      label: FOLDERS_BY_ID_LABEL, sql: FOLDERS_BY_ID_SQL,
      params: [{ name: "record_id", type: "text", max_len: 128 }] },
    // Task fb8564c: the authored Folders tab opts into inbound reveal with
    // the plain push-only string, last so existing order holds. SQL
    // statements/params above are unchanged.
    "surface.reveal.v1",
  ];
}
