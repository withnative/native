//! `query::tree` — the recursive containment walk over `records.home_id`.
//! Backs tool 2 (`get_structure`), the ancestor enrichment on `query::read`,
//! and subtree scoping on search/pipeline.
//!
//! Depth-limited **with per-node counts** by contract (decision 2231ad3,
//! workbench-driven): a node at the depth limit still reports how many live
//! children it has, so a UI can render "n more" without a second walk.
//!
//! Bounded on the other axis too (decision 5055a9c): `max_depth` alone does not
//! bound a walk, because one node with thousands of direct children returns all
//! of them at `depth: 1`. Siblings are capped per node, and `child_count`
//! already says what the cap is a window onto.

use std::collections::{HashMap, HashSet};

use serde::Serialize;
use sqlx::{Row, Sqlite, SqliteConnection, Transaction};

use super::lens::{ProjectionRead, ReadLens};
use crate::db::Db;
use crate::error::Result;
use crate::schema::{ARCHIVED_FACET_KEY, SPINE_TYPES};

use super::error::contract_violation;

/// Hard ceiling on any walk — a home_id cycle cannot hang the engine.
pub(crate) const MAX_WALK_DEPTH: i64 = 100;

/// Default cap on siblings returned per node. Matches
/// [`crate::query::read::DEFAULT_ENRICH_LIMIT`] — a tree node and a record pane
/// showing the same container should not disagree about how much is "a page".
pub const DEFAULT_MAX_CHILDREN_PER_NODE: i64 = 200;

/// Hard ceiling on `max_children_per_node`, mirroring
/// [`crate::query::read::MAX_ENRICH_LIMIT`].
pub const MAX_CHILDREN_PER_NODE: i64 = 1_000;

/// One node of a depth-limited containment walk, in depth-first order.
#[derive(Debug, Clone, Serialize)]
pub struct TreeNode {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
    pub home_id: Option<String>,
    pub persistence: String,
    pub last_activity_at: Option<String>,
    /// True when this record starts a different effective custody scope than
    /// its containment parent. The underlying policy anchor is deliberately
    /// never serialized.
    pub custody_boundary: bool,
    /// Whether every containment ancestor from the engine root to this record
    /// is visible to the caller. A false value is sufficient for clients to
    /// render a temporary Current bridge without learning which ancestor was
    /// hidden.
    pub containment_path_visible: bool,
    /// Depth below the walk root (the root itself is 0).
    pub depth: i64,
    /// Count of this node's LIVE (and, unless included, unarchived) children —
    /// counted even when `depth` sits at the limit, so truncation is visible.
    pub child_count: i64,
    pub archived: bool,
}

/// Options for [`descendants`].
#[derive(Debug, Clone)]
pub struct TreeOptions {
    /// Maximum depth below the root to descend (1 = children only).
    pub max_depth: i64,
    /// Include archived records in the walk (default false — the engine-wide
    /// default visibility rule).
    pub include_archived: bool,
    /// Cap on siblings emitted per node. A capped-out child is not walked
    /// into either, so the result is a whole subtree rather than a forest with
    /// orphans in it.
    pub max_children_per_node: i64,
    /// Explicit spine-type exclusions applied BEFORE child counts and the
    /// sibling cap. An excluded record never appears and its subtree is never
    /// walked, so counts describe the filtered walk rather than the unfiltered
    /// one. Empty preserves the unfiltered walk.
    pub exclude_types: Vec<String>,
}

impl Default for TreeOptions {
    fn default() -> Self {
        TreeOptions {
            max_depth: 3,
            include_archived: false,
            max_children_per_node: DEFAULT_MAX_CHILDREN_PER_NODE,
            exclude_types: Vec::new(),
        }
    }
}

/// SQL fragment for explicit type exclusion. Values are inlined as quoted
/// literals (single quotes escaped) so the caller's bind order stays
/// untouched — the same reason the archived filters inline `'archived'`.
/// Callers validate against the closed spine set; escaping keeps a direct
/// `TreeOptions` use safe regardless.
fn type_exclusion_clause(alias: &str, exclude_types: &[String]) -> String {
    if exclude_types.is_empty() {
        return String::new();
    }
    let mut seen = std::collections::HashSet::new();
    let mut literals = Vec::new();
    for value in exclude_types {
        if seen.insert(value.as_str()) {
            literals.push(format!("'{}'", value.replace('\'', "''")));
        }
    }
    if literals.is_empty() {
        return String::new();
    }
    format!("AND {alias}.type NOT IN ({})", literals.join(","))
}

/// Walk the containment tree from `root_id` downward, depth-first, returning
/// the root followed by its descendants. Tombstoned records never appear;
/// archived subtrees are skipped whole unless `include_archived`. Records
/// whose type appears in `exclude_types` are skipped whole in the same way —
/// before child counts and the sibling cap — while the root itself is still
/// emitted.
pub async fn descendants(db: &Db, root_id: &str, opts: TreeOptions) -> Result<Vec<TreeNode>> {
    descendants_inner(
        ProjectionRead::new(db),
        db.write_pool(),
        root_id,
        opts,
        None,
    )
    .await
}

/// Caller-relative containment walk. The sibling cap is applied after policy
/// filtering, so unreadable rows cannot consume a visible page slot or prune a
/// visible descendant's otherwise-readable sibling subtree.
pub async fn descendants_as(
    db: &Db,
    root_id: &str,
    opts: TreeOptions,
    principal: crate::authorization::Principal<'_>,
) -> Result<Vec<TreeNode>> {
    descendants_inner(
        ProjectionRead::new(db),
        db.write_pool(),
        root_id,
        opts,
        Some(principal),
    )
    .await
}

/// Historical-aware caller-relative containment walk. Tree content comes from
/// the replay projection while authorization remains anchored to live policy.
pub async fn descendants_with_lens_as(
    lens: &ReadLens<'_>,
    root_id: &str,
    opts: TreeOptions,
    principal: crate::authorization::Principal<'_>,
) -> Result<Vec<TreeNode>> {
    descendants_inner(
        lens.projection(),
        lens.meta().snapshot_pool(),
        root_id,
        opts,
        Some(principal),
    )
    .await
}

pub async fn descendants_from(
    projection: ProjectionRead<'_>,
    root_id: &str,
    opts: TreeOptions,
) -> Result<Vec<TreeNode>> {
    descendants_inner(projection, projection.snapshot_pool(), root_id, opts, None).await
}

async fn descendants_inner(
    projection: ProjectionRead<'_>,
    authorization_pool: &sqlx::SqlitePool,
    root_id: &str,
    opts: TreeOptions,
    principal: Option<crate::authorization::Principal<'_>>,
) -> Result<Vec<TreeNode>> {
    let db = projection.snapshot_pool();
    if opts.max_depth < 0 {
        return Err(contract_violation("tree max_depth must be >= 0"));
    }
    if opts.max_children_per_node < 0 {
        return Err(contract_violation(
            "tree max_children_per_node must be >= 0",
        ));
    }
    if opts.max_children_per_node > MAX_CHILDREN_PER_NODE {
        // The walk has no offset of its own, so the way past this ceiling is
        // `get_record` on the wide node — which does have one, and is
        // registered. Not `query_record`, which is stage 5 and unbuilt.
        return Err(contract_violation(format!(
            "tree max_children_per_node must be <= {MAX_CHILDREN_PER_NODE} \
             (to read past it, page that node with get_record and children_offset)"
        )));
    }
    for excluded in &opts.exclude_types {
        if !SPINE_TYPES.contains(&excluded.as_str()) {
            return Err(contract_violation(format!(
                "tree exclude_types entry '{excluded}' is not a spine type"
            )));
        }
    }
    let max_depth = opts.max_depth.min(MAX_WALK_DEPTH);
    let archived_walk_filter = if opts.include_archived {
        ""
    } else {
        "AND NOT EXISTS (SELECT 1 FROM facet_values av \
           WHERE av.record_id = r.id AND av.key = 'archived')"
    };
    let archived_count_filter = if opts.include_archived {
        ""
    } else {
        "AND NOT EXISTS (SELECT 1 FROM facet_values av \
           WHERE av.record_id = c.id AND av.key = 'archived')"
    };
    // Explicit type exclusions filter BEFORE counts and the sibling cap:
    // excluded rows never contribute to `child_count`, never consume a page
    // slot, and their subtrees are never walked because they never enter the
    // frontier. The root itself is still emitted — pointing at a record is
    // asking for it, the same rule archived records follow.
    let type_walk_filter = type_exclusion_clause("r", &opts.exclude_types);
    let type_count_filter = type_exclusion_clause("c", &opts.exclude_types);
    // The walk is driven level by level from here rather than by one recursive
    // CTE, and the reason is the sibling cap.
    //
    // Expressing the cap in SQL means a correlated `IN (SELECT … ORDER BY
    // name, id LIMIT ?)` in the recursive term, which SQLite re-evaluates per
    // candidate row — and each evaluation sorts the whole sibling set, because
    // the frozen DDL indexes `records(home_id)` and nothing finer. Measured
    // on a single node at `depth: 1`: **253 ms at 1,500 children and 2.4 s at
    // 5,000**, against ~1–3 ms for the same bound applied as a plain `LIMIT`
    // in `query::read`. A covering `(home_id, name, id)` index would fix it
    // and is not available — `ea7e5bd` closed the DDL to a second re-freeze.
    //
    // Level-driven, the cap is a Rust `take()` over one ordered read per level,
    // so the work is proportional to what is returned: capped-out children are
    // never expanded, and a cut node's subtree is never walked and discarded.
    // Same node at 5,000 children: 8.4 ms for 201 nodes, against the old
    // uncapped CTE's 13.5 ms for 5,001.
    //
    // It is not free. One statement per level replaces one statement total, so
    // a deep narrow chain pays round trips the CTE did not: a 40-level walk
    // measures 1.0 ms against the CTE's 0.24 ms. Sub-millisecond, at four times
    // the default depth, on the shape this call is least often asked for — the
    // trade is worth naming and not worth avoiding.
    let mut nodes: Vec<(String, TreeNode)> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let not_hidden = super::not_hidden_predicate("r");

    // The root is emitted whatever its archive state — pointing at a record is
    // asking for it, same rule `read::get_record` follows. Only the walk BELOW
    // it honours the visibility default. The same holds for `exclude_types`:
    // the root is emitted even when its own type is excluded.
    let cols = node_columns(archived_count_filter, &type_count_filter);
    let root_sql = format!(
        "SELECT {cols} FROM records r
          WHERE r.id = ? AND r.deleted_at IS NULL
            AND {not_hidden}"
    );
    let Some(row) = sqlx::query(&root_sql)
        .bind(ARCHIVED_FACET_KEY)
        .bind(root_id)
        .fetch_optional(db)
        .await?
    else {
        return Ok(Vec::new());
    };
    let mut root = node_from_row(&row, 0)?;
    if let Some(principal) = principal {
        root.child_count = authorized_child_count(
            projection,
            authorization_pool,
            &root.id,
            opts.include_archived,
            &opts.exclude_types,
            principal,
        )
        .await?;
        if let Some(home_id) = root.home_id.as_deref() {
            if !can_view(authorization_pool, principal, home_id).await {
                root.home_id = None;
            }
        }
    }
    visited.insert(root.id.clone());
    // Sort keys are id-paths, preserving the depth-first-by-id order the
    // recursive walk emitted. The cap keys on (name, id) instead — deliberately
    // the SAME key `query::read`'s children window uses. The two calls must
    // agree on WHICH children a capped container has; that they disagree on the
    // order to show them in is a UI concern (56642c0 open call B), and a much
    // smaller one than returning different sets would be.
    let root_path = format!(",{},", root.id);
    let mut frontier: Vec<Frontier> = vec![Frontier {
        id: root.id.clone(),
        path: root_path.clone(),
        child_count: root.child_count,
    }];
    nodes.push((root_path, root));

    for depth in 1..=max_depth {
        if frontier.is_empty() {
            break;
        }
        let mut next: Vec<Frontier> = Vec::new();
        let paths: HashMap<&str, &str> = frontier
            .iter()
            .map(|f| (f.id.as_str(), f.path.as_str()))
            .collect();
        let mut taken_from: HashMap<String, i64> = HashMap::new();

        // A parent is read one of two ways, decided by the `child_count` the
        // level above already reported.
        //
        // **Narrow parents share one statement.** Nothing they return will be
        // cut, so batching them costs no wasted rows and saves a round trip
        // each. Measured on 500 parents of 3 children: 2.4 ms batched against
        // 9.7 ms one statement apiece.
        //
        // **Wide parents get a bounded statement each**, so the cap reaches SQL
        // and only `cap` rows per parent ever cross into the process. Batching
        // those would fetch every child and discard the surplus in Rust — on 50
        // parents of 500 children, 25,000 rows and 33 ms against 10,000 rows and
        // 14.8 ms. Wide parents are rare (12 of 5,335 containers in the
        // reference corpus exceed 200), so this path runs seldom and matters
        // enormously when it does.
        let (wide, narrow): (Vec<&Frontier>, Vec<&Frontier>) = frontier
            .iter()
            .partition(|f| f.child_count > opts.max_children_per_node);

        let mut rows = Vec::new();
        for parent in &wide {
            let limit = if principal.is_some() { "" } else { "LIMIT ?" };
            let sql = format!(
                "SELECT {cols}
                   FROM records r
                  WHERE r.home_id = ? AND r.deleted_at IS NULL
                    AND {not_hidden}
                    {archived_walk_filter}
                    {type_walk_filter}
                  ORDER BY r.name, r.id {limit}"
            );
            let query = sqlx::query(&sql).bind(ARCHIVED_FACET_KEY).bind(&parent.id);
            let query = if principal.is_some() {
                query
            } else {
                query.bind(opts.max_children_per_node)
            };
            rows.extend(query.fetch_all(db).await?);
        }
        // Chunked because a level's parent count is bounded only by the product
        // of the cap and the levels above it, which can exceed SQLite's host
        // parameter limit long before it exceeds memory.
        for chunk in narrow.chunks(PARENT_CHUNK) {
            let placeholders = std::iter::repeat_n("?", chunk.len())
                .collect::<Vec<_>>()
                .join(",");
            let sql = format!(
                "SELECT {cols}
                   FROM records r
                  WHERE r.home_id IN ({placeholders}) AND r.deleted_at IS NULL
                    AND {not_hidden}
                    {archived_walk_filter}
                    {type_walk_filter}
                  ORDER BY r.home_id, r.name, r.id"
            );
            let mut q = sqlx::query(&sql).bind(ARCHIVED_FACET_KEY);
            for parent in chunk {
                q = q.bind(&parent.id);
            }
            rows.extend(q.fetch_all(db).await?);
        }

        for row in &rows {
            let mut node = node_from_row(row, depth)?;
            let Some(parent) = node.home_id.clone() else {
                continue;
            };
            if let Some(principal) = principal {
                let visible = crate::authorization::effective_capability_in_pool(
                    authorization_pool,
                    principal,
                    &node.id,
                )
                .await
                .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View));
                if !visible {
                    continue;
                }
                node.child_count = authorized_child_count(
                    projection,
                    authorization_pool,
                    &node.id,
                    opts.include_archived,
                    &opts.exclude_types,
                    principal,
                )
                .await?;
            }
            // Rows arrive in (name, id) order within each parent either way, so
            // a per-parent counter is the sibling rank. Still applied to the
            // wide path, where SQL has already done it: `child_count` is read a
            // level earlier than the rows it describes, so a concurrent insert
            // between the two would otherwise slip past the cap.
            let taken = taken_from.entry(parent.clone()).or_insert(0);
            if *taken >= opts.max_children_per_node {
                continue;
            }
            *taken += 1;
            // The cycle guard the `path` column used to carry. home_id is
            // single-valued, so a repeat id means a loop, not a diamond.
            if !visited.insert(node.id.clone()) {
                continue;
            }
            let path = format!("{}{},", paths[parent.as_str()], node.id);
            next.push(Frontier {
                id: node.id.clone(),
                path: path.clone(),
                child_count: node.child_count,
            });
            nodes.push((path, node));
        }
        frontier = next;
    }

    nodes.sort_by(|(a, _), (b, _)| a.cmp(b));
    let root_path_visible = match principal {
        None => true,
        Some(principal) => {
            containment_path_visible(projection, authorization_pool, root_id, principal).await?
        }
    };
    for (_, node) in &mut nodes {
        let authored_home: Option<String> =
            sqlx::query_scalar("SELECT home_id FROM records WHERE id = ?")
                .bind(&node.id)
                .fetch_optional(db)
                .await?
                .flatten();
        node.custody_boundary =
            custody_boundary_in_pool(authorization_pool, &node.id, authored_home.as_deref())
                .await?;
        node.containment_path_visible = root_path_visible;
    }
    Ok(nodes.into_iter().map(|(_, node)| node).collect())
}

/// Largest `home_id IN (…)` list per statement — comfortably under SQLite's
/// default host-parameter ceiling with room for the bound `archived` key.
const PARENT_CHUNK: usize = 500;

/// One pending parent: where it sits in the emitted order, and how many
/// children the level above said it has — which is what decides whether it is
/// read in a batch or on its own.
struct Frontier {
    id: String,
    path: String,
    child_count: i64,
}

/// The node projection, shared by the root fetch and both level strategies so
/// they cannot drift apart in what they select. Every statement using it binds
/// the `archived` key first.
fn node_columns(archived_count_filter: &str, type_count_filter: &str) -> String {
    let not_hidden = super::not_hidden_predicate("c");
    format!(
        "r.id, r.type, r.kind, r.name, r.home_id, r.persistence,
         r.last_activity_at,
         (SELECT COUNT(*) FROM records c
           WHERE c.home_id = r.id AND c.deleted_at IS NULL
             AND {not_hidden}
           {archived_count_filter}
           {type_count_filter}) AS child_count,
         EXISTS (SELECT 1 FROM facet_values av
                  WHERE av.record_id = r.id AND av.key = ?) AS archived"
    )
}

fn node_from_row(row: &sqlx::sqlite::SqliteRow, depth: i64) -> Result<TreeNode> {
    Ok(TreeNode {
        id: row.try_get("id")?,
        record_type: row.try_get("type")?,
        kind: row.try_get("kind")?,
        name: row.try_get("name")?,
        home_id: row.try_get("home_id")?,
        persistence: row.try_get("persistence")?,
        last_activity_at: row.try_get("last_activity_at")?,
        custody_boundary: false,
        containment_path_visible: false,
        depth,
        child_count: row.try_get("child_count")?,
        archived: row.try_get::<i64, _>("archived")? != 0,
    })
}

pub(crate) async fn custody_boundary_in_pool(
    pool: &sqlx::SqlitePool,
    record_id: &str,
    home_id: Option<&str>,
) -> Result<bool> {
    let mut connection = pool.acquire().await?;
    custody_boundary_on(&mut connection, record_id, home_id).await
}

pub(crate) async fn custody_boundary_in(
    transaction: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    home_id: Option<&str>,
) -> Result<bool> {
    custody_boundary_on(transaction, record_id, home_id).await
}

async fn custody_boundary_on(
    connection: &mut SqliteConnection,
    record_id: &str,
    home_id: Option<&str>,
) -> Result<bool> {
    let Some(home_id) = home_id else {
        return Ok(false);
    };
    let row = sqlx::query(
        "SELECT child.policy_anchor_id AS child_anchor,
                parent.policy_anchor_id AS parent_anchor
           FROM records child
           JOIN records parent ON parent.id = ?
          WHERE child.id = ?",
    )
    .bind(home_id)
    .bind(record_id)
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else {
        return Ok(false);
    };
    let child: Option<String> = row.try_get("child_anchor")?;
    let parent: Option<String> = row.try_get("parent_anchor")?;
    Ok(child.is_some() && parent.is_some() && child != parent)
}

pub(crate) async fn containment_path_visible(
    projection: ProjectionRead<'_>,
    authorization_pool: &sqlx::SqlitePool,
    record_id: &str,
    principal: crate::authorization::Principal<'_>,
) -> Result<bool> {
    if record_id == crate::schema::ROOT_RECORD_ID {
        return Ok(true);
    }
    let ancestors = ancestors_from(projection, record_id).await?;
    if ancestors.first().map(|entry| entry.id.as_str()) != Some(crate::schema::ROOT_RECORD_ID) {
        return Ok(false);
    }
    for ancestor in ancestors {
        if !can_view(authorization_pool, principal, &ancestor.id).await {
            return Ok(false);
        }
    }
    Ok(true)
}

pub(crate) async fn containment_path_visible_in(
    transaction: &mut Transaction<'_, Sqlite>,
    record_id: &str,
    principal: crate::authorization::Principal<'_>,
) -> Result<bool> {
    if record_id == crate::schema::ROOT_RECORD_ID {
        return Ok(true);
    }
    let ancestors = ancestors_on(transaction, record_id).await?;
    if ancestors.first().map(|entry| entry.id.as_str()) != Some(crate::schema::ROOT_RECORD_ID) {
        return Ok(false);
    }
    for ancestor in ancestors {
        if !can_view_in(transaction, principal, &ancestor.id).await {
            return Ok(false);
        }
    }
    Ok(true)
}

async fn can_view(
    authorization_pool: &sqlx::SqlitePool,
    principal: crate::authorization::Principal<'_>,
    record_id: &str,
) -> bool {
    crate::authorization::effective_capability_in_pool(authorization_pool, principal, record_id)
        .await
        .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View))
}

async fn can_view_in(
    transaction: &mut Transaction<'_, Sqlite>,
    principal: crate::authorization::Principal<'_>,
    record_id: &str,
) -> bool {
    crate::authorization::effective_capability_on(transaction, principal, record_id)
        .await
        .is_ok_and(|capability| capability.allows(crate::authorization::Capability::View))
}

async fn authorized_child_count(
    projection: ProjectionRead<'_>,
    authorization_pool: &sqlx::SqlitePool,
    record_id: &str,
    include_archived: bool,
    exclude_types: &[String],
    principal: crate::authorization::Principal<'_>,
) -> Result<i64> {
    let archived_filter = if include_archived {
        ""
    } else {
        "AND NOT EXISTS (SELECT 1 FROM facet_values av
                          WHERE av.record_id = r.id AND av.key = 'archived')"
    };
    let type_filter = type_exclusion_clause("r", exclude_types);
    let sql = format!(
        "SELECT r.id FROM records r
          WHERE r.home_id = ? AND r.deleted_at IS NULL
            AND {} {archived_filter} {type_filter}",
        super::not_hidden_predicate("r")
    );
    let ids: Vec<String> = sqlx::query_scalar(&sql)
        .bind(record_id)
        .fetch_all(projection.shared_pool())
        .await?;
    let mut count = 0;
    for id in ids {
        if can_view(authorization_pool, principal, &id).await {
            count += 1;
        }
    }
    Ok(count)
}

/// One entry of an ancestor chain.
#[derive(Debug, Clone, Serialize)]
pub struct AncestorEntry {
    pub id: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub kind: Option<String>,
    pub name: String,
}

/// The containment chain of `id`, ROOT FIRST, excluding `id` itself. Cycle-safe;
/// tombstoned ancestors still appear (a child cannot repair its parentage).
pub async fn ancestors(db: &Db, id: &str) -> Result<Vec<AncestorEntry>> {
    ancestors_from(ProjectionRead::new(db), id).await
}

pub async fn ancestors_from(
    projection: ProjectionRead<'_>,
    id: &str,
) -> Result<Vec<AncestorEntry>> {
    let db = projection.snapshot_pool();
    let rows = sqlx::query(
        "WITH RECURSIVE up(id, depth, path) AS (
            SELECT r.home_id, 1, ',' || ? || ','
              FROM records r WHERE r.id = ? AND r.home_id IS NOT NULL
            UNION ALL
            SELECT r.home_id, u.depth + 1, u.path || u.id || ','
              FROM records r JOIN up u ON r.id = u.id
              WHERE r.home_id IS NOT NULL AND u.depth < ?
                AND instr(u.path, ',' || r.home_id || ',') = 0
          )
          SELECT r.id, r.type, r.kind, r.name, u.depth
          FROM up u JOIN records r ON r.id = u.id
          ORDER BY u.depth DESC",
    )
    .bind(id)
    .bind(id)
    .bind(MAX_WALK_DEPTH)
    .fetch_all(db)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AncestorEntry {
                id: row.try_get("id")?,
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                name: row.try_get("name")?,
            })
        })
        .collect()
}

pub(crate) async fn ancestors_on(
    conn: &mut SqliteConnection,
    id: &str,
) -> Result<Vec<AncestorEntry>> {
    let rows = sqlx::query(
        "WITH RECURSIVE up(id, depth, path) AS (
            SELECT r.home_id, 1, ',' || ? || ','
              FROM records r WHERE r.id = ? AND r.home_id IS NOT NULL
            UNION ALL
            SELECT r.home_id, u.depth + 1, u.path || u.id || ','
              FROM records r JOIN up u ON r.id = u.id
              WHERE r.home_id IS NOT NULL AND u.depth < ?
                AND instr(u.path, ',' || r.home_id || ',') = 0
          )
          SELECT r.id, r.type, r.kind, r.name, u.depth
          FROM up u JOIN records r ON r.id = u.id
          ORDER BY u.depth DESC",
    )
    .bind(id)
    .bind(id)
    .bind(MAX_WALK_DEPTH)
    .fetch_all(conn)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(AncestorEntry {
                id: row.try_get("id")?,
                record_type: row.try_get("type")?,
                kind: row.try_get("kind")?,
                name: row.try_get("name")?,
            })
        })
        .collect()
}

/// The ids of `root_id`'s subtree (root included), for scoping other reads.
/// Live, unarchived records only. Archived folders prune their whole browse
/// subtree so scoped browse and scoped search expose the same reachable set.
pub(crate) async fn subtree_ids(db: &Db, root_id: &str) -> Result<Vec<String>> {
    subtree_ids_with_hidden(db, root_id, false, false, false).await
}

/// The canonical default subtree read on a caller-owned connection.
///
/// Snapshot-sensitive queries use this form so membership and their other
/// read decisions share one SQLite transaction rather than approximating the
/// subtree contract with a second SQL implementation.
pub(crate) async fn subtree_ids_in(
    conn: &mut SqliteConnection,
    root_id: &str,
) -> Result<Vec<String>> {
    subtree_ids_with_hidden_in(conn, root_id, false, false, false).await
}

/// Pipeline queries can opt each hidden family into subtree addressing
/// independently. Other callers retain the default-hidden contract through
/// [`subtree_ids`].
pub(crate) async fn subtree_ids_with_hidden(
    db: &Db,
    root_id: &str,
    include_suggestions: bool,
    include_citations: bool,
    include_archived: bool,
) -> Result<Vec<String>> {
    let mut conn = db.write_pool().acquire().await?;
    subtree_ids_with_hidden_in(
        &mut conn,
        root_id,
        include_suggestions,
        include_citations,
        include_archived,
    )
    .await
}

pub(crate) async fn subtree_ids_with_hidden_in(
    conn: &mut SqliteConnection,
    root_id: &str,
    include_suggestions: bool,
    include_citations: bool,
    include_archived: bool,
) -> Result<Vec<String>> {
    let hidden_filter = format!(
        "AND {}",
        super::hidden_visibility_predicate("r", include_suggestions, include_citations, false)
    );
    let archived_filter = if include_archived {
        String::new()
    } else {
        format!(
            "AND NOT EXISTS (SELECT 1 FROM facet_values a WHERE a.record_id = r.id AND a.key = '{ARCHIVED_FACET_KEY}')"
        )
    };
    let sql = format!(
        "WITH RECURSIVE walk(id, depth, path) AS (
            SELECT r.id, 0, ',' || r.id || ','
              FROM records r WHERE r.id = ? AND r.deleted_at IS NULL
                {hidden_filter}
                {archived_filter}
            UNION ALL
            SELECT r.id, w.depth + 1, w.path || r.id || ','
              FROM records r JOIN walk w ON r.home_id = w.id
              WHERE w.depth < ? AND r.deleted_at IS NULL
                {hidden_filter}
                {archived_filter}
                AND instr(w.path, ',' || r.id || ',') = 0
          )
          SELECT id FROM walk"
    );
    let rows = sqlx::query(&sql)
        .bind(root_id)
        .bind(MAX_WALK_DEPTH)
        .fetch_all(&mut *conn)
        .await?;
    rows.iter()
        .map(|row| Ok(row.try_get::<String, _>("id")?))
        .collect()
}
