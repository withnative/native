//! Purpose-relative briefing assembler, dogfood slice 1: deterministic core.
//!
//! This module is authorisation-first and transport-neutral. It has NO MCP
//! operation yet: [`assemble`] walks a bounded neighbourhood around explicit
//! focal records, filters every candidate id through the caller's `View`
//! capability BEFORE reading anything beyond ids, and returns nodes plus
//! machine-readable [`Receipt`]s for everything cut. Standing and ranking
//! arrive in a later sub-step; this slice is types + bounded walk +
//! authorisation only.
//!
//! Scope note: frame and neighbourhood edges are the physical `links` table,
//! which carries both content-owned link types AND the compatibility rows the
//! relationship projector writes for governed relationships with
//! `effective_state = 'active'` (`project_compatibility_link_in` in
//! `src/relationship/projector.rs`, ids like `rel:{origin}:{relationship_id}`).
//! A governed edge asserted through the production relationship path therefore
//! reaches this walk; a raw `link.added` event with a relationship-owned token
//! does not, because live projection early-returns it before the table.
//!
//! Fan-out streams each backbone node's neighbourhood in SQL `ORDER BY ...`
//! `LIMIT` pages and authorises page by page, so one high-degree node never
//! materialises its full link set. Pages run to exhaustion, which keeps the
//! [`Receipt::FanoutCapped`] `omitted` count exact over visible neighbours
//! (an early stop would turn it into a lower bound).
//!
//! The [`NODE_CAP`] node cap is applied BEFORE standing is known and is
//! standing-agnostic: victims are cut in walk order (relation, distance,
//! id), not in rank order (class, basis, ...), so the cut can keep the
//! walk-front while dropping the eventual rank-front. [`assemble_briefing`]
//! inherits the walk's cut as-is; [`Receipt::NodeCapReached`] tells the
//! caller the view is incomplete.

use std::collections::{HashMap, HashSet};

use sqlx::Row;

use crate::db::Db;
use crate::error::Result;

use super::super::registry::Caller;
use super::{is_legacy_local, principal, visible_ids_in_pool};

/// Maximum frame-walk depth: focal record, its frame, and the frame's frame.
pub const FRAME_DEPTH: usize = 2;
/// Maximum neighbours admitted per node in the one-hop neighbourhood pass.
pub const FANOUT_PER_NODE: usize = 12;
/// Maximum nodes in the whole walk, focal records included.
pub const NODE_CAP: usize = 60;
/// A home with more live children than this is a broad folder: named but
/// never examined as a frame.
pub const BROAD_FOLDER_CHILDREN: usize = 50;

/// Upward edges the frame walk follows. `home_id` is conditional (see
/// [`frame_parents`]); the three link types are unconditional.
const FRAME_RELATIONSHIPS: [&str; 3] = ["part_of", "derived_from", "implements"];

/// Why a record is in the walk. Enum order IS distance order: a focal
/// record's own neighbours (distance 1) sort before frame neighbours
/// (distance 2) at cap and rank time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Relation {
    Focal,
    Frame,
    FocalNeighbour,
    FrameNeighbour,
}

/// What the walk is relative to.
#[derive(Debug, Clone)]
pub struct Purpose {
    pub focal: Vec<String>,
    /// Point-in-time horizon. Unused in slice 1a: the walk always reads the
    /// live set. Kept so the signature already names the future parameter.
    pub as_of: Option<String>,
}

/// Bounds that shaped a walk. Kept beside the receipts so a later ranking
/// step can distinguish "nothing more existed" from "more existed but cut".
#[derive(Debug, Clone, Default)]
pub struct BriefingBounds {
    pub frame_depth: usize,
    pub fanout_per_node: usize,
    pub node_cap: usize,
}

/// One walked record.
#[derive(Debug, Clone)]
pub struct Node {
    pub id: String,
    pub name: String,
    pub type_: String,
    pub kind: String,
    pub relation: Relation,
    pub distance: u8,
    /// The edge that admitted this node: (relationship, source id).
    /// `home` marks a `home_id` containment edge; `None` marks a focal root.
    pub via: Option<(String, String)>,
    // Structural facts for the standing pass. All read after the visibility
    // filter, so a hidden record's facts never enter the briefing.
    pub maturity: Option<String>,
    pub lifecycle: Option<String>,
    pub home_id: Option<String>,
    pub archived: bool,
    /// `COALESCE(last_activity_at, updated_at, created_at)`: the FINAL
    /// ranking tie-break, newest first. ISO timestamps, so string order is
    /// chronological order.
    pub recency: String,
}

/// A machine-readable record of something the walk cut.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Receipt {
    FanoutCapped { node: String, omitted: usize },
    NodeCapReached { omitted: usize },
    BroadFolderNotExamined { folder_id: String },
    SystemContainerNotExamined { folder_id: String },
}

/// The assembled walk: nodes plus receipts plus the bounds that shaped them.
#[derive(Debug, Clone, Default)]
pub struct Walk {
    pub nodes: Vec<Node>,
    pub receipts: Vec<Receipt>,
    pub bounds: BriefingBounds,
}

/// The walk's admission table: node id -> (relation, distance, via edge).
type Admission = HashMap<String, (Relation, u8, Option<(String, String)>)>;

/// Structural facts read for one admitted node (step 7 of [`assemble`]).
struct NodeMeta {
    name: String,
    type_: String,
    kind: String,
    maturity: Option<String>,
    lifecycle: Option<String>,
    home_id: Option<String>,
    archived: bool,
    recency: String,
}

/// A home that was cut instead of framed: the receipt is emitted only after
/// the visibility pass, and only when the caller may View the home itself.
/// Hidden homes produce nothing — no node, no receipt, no id anywhere.
struct HomeCandidate {
    home_id: String,
    /// True for a system container (`native:*`), false for a broad folder.
    is_system: bool,
}

/// Frame parents of one record: targets of its outgoing `part_of`,
/// `derived_from`, and `implements` links, plus its `home_id` ONLY when that
/// home is live, not a system container, and either a WorkItem or a record
/// with at most [`BROAD_FOLDER_CHILDREN`] VISIBLE live children (hidden
/// children never flip the frame/broad bit). A cut home is NOT
/// receipted here: it is returned as a [`HomeCandidate`] so [`assemble`] can
/// emit [`Receipt::BroadFolderNotExamined`] / [`Receipt::SystemContainerNotExamined`]
/// after the visibility pass, and only for visible homes. Deleted
/// targets never surface: every leg filters `deleted_at IS NULL`.
async fn frame_parents(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    record_id: &str,
) -> Result<(Vec<(String, String)>, Option<HomeCandidate>)> {
    let mut parents: Vec<(String, String)> = Vec::new();
    let rel_json = serde_json::to_string(&FRAME_RELATIONSHIPS)?;
    let rows = sqlx::query(
        "SELECT l.target_id AS id, l.relationship AS rel FROM links l \
           JOIN records r ON r.id = l.target_id \
          WHERE l.source_id = ?1 AND r.deleted_at IS NULL \
            AND l.relationship IN (SELECT value FROM json_each(?2))",
    )
    .bind(record_id)
    .bind(rel_json)
    .fetch_all(pool)
    .await?;
    for row in rows {
        parents.push((row.try_get("id")?, row.try_get("rel")?));
    }
    let home: Option<(String, String)> = sqlx::query(
        "SELECT h.id AS id, h.type AS type_ FROM records h \
           WHERE h.id = (SELECT home_id FROM records WHERE id = ?1) \
             AND h.deleted_at IS NULL AND h.id <> ?1",
    )
    .bind(record_id)
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|row| Ok::<_, sqlx::Error>((row.try_get("id")?, row.try_get("type_")?)))
    .collect::<std::result::Result<Vec<_>, _>>()?
    .into_iter()
    .next();
    // Deterministic admission order: relationship, then id. Tuples are
    // (id, relationship), so sort the fields explicitly, not the tuple.
    parents.sort_by(|a, b| (a.1.as_str(), a.0.as_str()).cmp(&(b.1.as_str(), b.0.as_str())));
    if let Some((home_id, home_type)) = home {
        if home_id.starts_with("native:") {
            // System containers (native:root, native:unfiled, ...) are filing
            // infrastructure, never frames: unfiled in particular would put
            // unrelated records next to each other. Cut regardless of size;
            // the receipt waits for the visibility pass (see `assemble`).
            Ok((
                parents,
                Some(HomeCandidate {
                    home_id,
                    is_system: true,
                }),
            ))
        } else if home_type == "WorkItem" {
            // A WorkItem home is always a frame, however many children it
            // has. A hidden one still vanishes in the visibility pass.
            parents.push((home_id, "home".to_string()));
            Ok((parents, None))
        } else if visible_child_count(pool, caller, &home_id).await? <= BROAD_FOLDER_CHILDREN {
            parents.push((home_id, "home".to_string()));
            Ok((parents, None))
        } else {
            Ok((
                parents,
                Some(HomeCandidate {
                    home_id,
                    is_system: false,
                }),
            ))
        }
    } else {
        Ok((parents, None))
    }
}

/// Visible live children of `home_id`, capped: counts only children the
/// caller may View, and stops paging as soon as the count exceeds
/// [`BROAD_FOLDER_CHILDREN`]. Child ids stream in `ORDER BY id` pages so one
/// broad home never materialises its full kid set.
async fn visible_child_count(
    pool: &sqlx::SqlitePool,
    caller: &Caller,
    home_id: &str,
) -> Result<usize> {
    const PAGE: i64 = 200;
    let mut visible_count = 0usize;
    let mut offset = 0i64;
    loop {
        let rows = sqlx::query(
            "SELECT id FROM records \
              WHERE home_id = ?1 AND deleted_at IS NULL \
              ORDER BY id LIMIT ?2 OFFSET ?3",
        )
        .bind(home_id)
        .bind(PAGE)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        if rows.is_empty() {
            break;
        }
        let page: Vec<String> = rows
            .iter()
            .map(|row| row.try_get("id"))
            .collect::<std::result::Result<_, sqlx::Error>>()?;
        let page_len = page.len();
        let seen = visible_ids_in_pool(pool, caller, page).await?;
        visible_count += seen.len();
        if visible_count > BROAD_FOLDER_CHILDREN {
            break;
        }
        if page_len < PAGE as usize {
            break;
        }
        offset += PAGE;
    }
    Ok(visible_count)
}

/// Explicit focal ids plus the visible-is-filtered-later head of each:
/// records with an incoming `supersedes` link TO a focal record (i.e. rows
/// whose `source_id` supersedes the focal `target_id`). Live successors
/// only; the visibility filter in [`assemble`] decides which survive.
async fn focal_with_heads(pool: &sqlx::SqlitePool, focal: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = focal.to_vec();
    if focal.is_empty() {
        return Ok(out);
    }
    // One JSON-array bind for the whole id set (the `overlap_neighbourhood`
    // pattern in work.rs): one placeholder per id would spend SQLite's
    // variable budget on the focal list itself.
    let ids_json = serde_json::to_string(focal)?;
    let rows = sqlx::query(
        "SELECT DISTINCT l.source_id AS id FROM links l \
           JOIN records s ON s.id = l.source_id \
          WHERE l.relationship = 'supersedes' AND s.deleted_at IS NULL \
            AND l.target_id IN (SELECT value FROM json_each(?)) \
          ORDER BY l.source_id",
    )
    .bind(ids_json)
    .fetch_all(pool)
    .await?;
    for row in rows {
        let id: String = row.try_get("id")?;
        if !out.contains(&id) {
            out.push(id);
        }
    }
    Ok(out)
}

/// One ordered neighbour candidate: (neighbour id, relationship).
#[derive(Debug, Clone)]
struct NeighbourCandidate {
    id: String,
    relationship: String,
}

/// One page of the links touching `node_id`, in deterministic priority
/// order: frame-type edges first, then `relationship` ASC, neighbour id ASC,
/// link id ASC. No timestamps anywhere: recency never decides which
/// neighbours survive the fan-out cut (it only breaks ties at final rank).
/// Live neighbours only. Visibility is NOT checked here — [`assemble`]
/// intersects each page with the caller's `View` set, so fan-out receipts
/// count visible neighbours only.
async fn ordered_neighbour_page(
    pool: &sqlx::SqlitePool,
    node_id: &str,
    limit: i64,
    offset: i64,
) -> Result<Vec<NeighbourCandidate>> {
    let rows = sqlx::query(
        "SELECT l.id AS link_id, l.relationship AS rel, \
                CASE WHEN l.source_id = ?1 THEN l.target_id ELSE l.source_id END AS other \
           FROM links l JOIN records o \
             ON o.id = CASE WHEN l.source_id = ?1 THEN l.target_id ELSE l.source_id END \
          WHERE (l.source_id = ?1 OR l.target_id = ?1) AND o.deleted_at IS NULL \
          ORDER BY CASE WHEN l.relationship IN ('part_of', 'derived_from', 'implements') \
                        THEN 0 ELSE 1 END, \
                   l.relationship, other, l.id \
          LIMIT ?2 OFFSET ?3",
    )
    .bind(node_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for row in rows {
        out.push(NeighbourCandidate {
            id: row.try_get("other")?,
            relationship: row.try_get("rel")?,
        });
    }
    Ok(out)
}

/// Assemble the bounded, authorised walk for a purpose.
///
/// Order of operations is the contract: collect candidate ids (focal +
/// heads, frame, cut homes), filter that set through the caller's `View`
/// capability, admit the backbone, then stream each backbone node's
/// neighbourhood in authorised SQL pages. Only then read name/type/kind.
/// Hidden records appear nowhere — not in nodes, not in receipts, not in
/// counts. Final node order is by (relation, distance, id): identical
/// inputs give identical output.
pub async fn assemble(db: &Db, caller: &Caller, purpose: &Purpose) -> Result<Walk> {
    let pool = db.write_pool();
    let mut walk = Walk {
        bounds: BriefingBounds {
            frame_depth: FRAME_DEPTH,
            fanout_per_node: FANOUT_PER_NODE,
            node_cap: NODE_CAP,
        },
        ..Walk::default()
    };

    // 1. Focal: explicit ids plus live superseding heads. Dedupe, then drop
    // deleted focal ids before they can shape the walk.
    let focal_candidates = focal_with_heads(pool, &purpose.focal).await?;
    let mut focal: Vec<String> = Vec::new();
    for id in focal_candidates {
        if focal.contains(&id) {
            continue;
        }
        let live: bool =
            sqlx::query("SELECT COUNT(*) AS n FROM records WHERE id = ?1 AND deleted_at IS NULL")
                .bind(&id)
                .fetch_one(pool)
                .await?
                .try_get::<i64, _>("n")?
                != 0;
        if live {
            focal.push(id);
        }
    }

    // 2. Frame: breadth-first up FRAME_DEPTH levels from every focal root.
    // `frame_of` maps frame id -> (distance, via). Focal ids win ties: a
    // frame candidate that is already focal stays focal. Cut homes are NOT
    // receipted here: `frame_parents` returns them as candidates, and the
    // receipts wait for the step-4 visibility pass (hidden homes vanish
    // silently, never naming their ids).
    let focal_set: HashSet<String> = focal.iter().cloned().collect();
    let mut frame_of: HashMap<String, (u8, (String, String))> = HashMap::new();
    let mut home_candidates: HashMap<String, bool> = HashMap::new();
    let mut frontier: Vec<(String, u8)> = focal.iter().map(|id| (id.clone(), 0u8)).collect();
    for _ in 0..FRAME_DEPTH {
        let mut next = Vec::new();
        // Deterministic level order: sort the frontier by id.
        frontier.sort();
        for (current, distance) in &frontier {
            let (parents, candidate) = frame_parents(pool, caller, current).await?;
            if let Some(candidate) = candidate {
                home_candidates
                    .entry(candidate.home_id)
                    .or_insert(candidate.is_system);
            }
            for (parent, rel) in parents {
                if focal_set.contains(&parent) || frame_of.contains_key(&parent) {
                    continue;
                }
                frame_of.insert(parent.clone(), (distance + 1, (rel, current.clone())));
                next.push((parent, distance + 1));
            }
        }
        frontier = next;
    }

    // 3. Neighbourhood backbone: focal first, then frame by id. Neighbour
    // ids stream per node in step 5b (SQL pages, authorised page by page),
    // so only focal, frame, and cut-home candidates join the single pass.
    let mut backbone: Vec<String> = focal.clone();
    let mut frame_ids: Vec<String> = frame_of.keys().cloned().collect();
    frame_ids.sort();
    backbone.extend(frame_ids.iter().cloned());
    // Full candidate id set for the single authorisation pass. Cut-home
    // candidates join it so their receipts can be gated on visibility.
    let mut all_ids: HashSet<String> = focal_set.clone();
    for id in frame_of.keys() {
        all_ids.insert(id.clone());
    }
    for id in home_candidates.keys() {
        all_ids.insert(id.clone());
    }
    // 4. Authorise BEFORE reading anything beyond ids.
    let visible = visible_ids_in_pool(pool, caller, all_ids.into_iter().collect()).await?;

    // 4b. Not-examined receipts, post-auth: only for homes the caller may
    // View. Hidden homes produce nothing — no receipt, and their ids appear
    // nowhere in the output.
    for (home_id, is_system) in &home_candidates {
        if !visible.contains(home_id) {
            continue;
        }
        let receipt = if *is_system {
            Receipt::SystemContainerNotExamined {
                folder_id: home_id.clone(),
            }
        } else {
            Receipt::BroadFolderNotExamined {
                folder_id: home_id.clone(),
            }
        };
        if !walk.receipts.contains(&receipt) {
            walk.receipts.push(receipt);
        }
    }

    // 5. Admit nodes. Focal and frame nodes the caller cannot see vanish
    // silently — no receipts for authorisation cuts, only for bound cuts.
    let mut admission: Admission = HashMap::new();
    for id in &focal {
        if visible.contains(id) {
            admission.insert(id.clone(), (Relation::Focal, 0, None));
        }
    }
    for (id, (distance, via)) in &frame_of {
        if visible.contains(id) {
            admission.insert(id.clone(), (Relation::Frame, *distance, Some(via.clone())));
        }
    }
    // Neighbours, per node: one hop in and out on all link types, streamed
    // in SQL pages and authorised page by page — the selection below runs
    // on VISIBLE candidates only, so hidden records never consume fan-out.
    // A neighbour already admitted (as focal/frame, or via an earlier node)
    // is not re-counted against either node's fan-out.
    // Nodes are processed in backbone order (focal first, then frame by id)
    // so the cap-outcome is deterministic.
    const NEIGHBOUR_PAGE: i64 = 100;
    let mut omitted_by_node: Vec<(String, usize)> = Vec::new();
    for node_id in &backbone {
        if !admission.contains_key(node_id) {
            continue; // hidden backbone node: emits no neighbours, no receipt.
        }
        let is_focal = focal_set.contains(node_id);
        let relation = if is_focal {
            Relation::FocalNeighbour
        } else {
            Relation::FrameNeighbour
        };
        let distance = if is_focal { 1u8 } else { 2u8 };
        let mut taken = 0usize;
        let mut omitted = 0usize;
        let mut offset = 0i64;
        loop {
            let page = ordered_neighbour_page(pool, node_id, NEIGHBOUR_PAGE, offset).await?;
            if page.is_empty() {
                break;
            }
            let page_len = page.len();
            // Never re-admit a backbone node as its own neighbour: drop
            // backbone ids before authorising the page.
            let fresh: Vec<NeighbourCandidate> = page
                .into_iter()
                .filter(|c| !focal_set.contains(&c.id) && !frame_of.contains_key(&c.id))
                .collect();
            let ids: Vec<String> = fresh.iter().map(|c| c.id.clone()).collect();
            let page_visible = if ids.is_empty() {
                HashSet::new()
            } else {
                visible_ids_in_pool(pool, caller, ids).await?
            };
            for c in &fresh {
                if !page_visible.contains(&c.id) {
                    continue;
                }
                if admission.contains_key(&c.id) {
                    continue;
                }
                if taken >= FANOUT_PER_NODE {
                    omitted += 1;
                    continue;
                }
                admission.insert(
                    c.id.clone(),
                    (
                        relation,
                        distance,
                        Some((c.relationship.clone(), node_id.clone())),
                    ),
                );
                taken += 1;
            }
            if page_len < NEIGHBOUR_PAGE as usize {
                break;
            }
            offset += NEIGHBOUR_PAGE;
        }
        if omitted > 0 {
            omitted_by_node.push((node_id.clone(), omitted));
        }
    }

    // 6. Node cap: deterministic victim order is the walk order
    // (relation, distance, id) — cut from the back, keep the front. This
    // runs BEFORE standing is known and is standing-agnostic by design: it
    // can drop the eventual rank-front while keeping the walk-front (see
    // the module header). The Briefing inherits this cut; NodeCapReached
    // tells the caller the view is incomplete.
    let mut ordered: Vec<(String, Relation, u8)> = admission
        .iter()
        .map(|(id, (rel, dist, _))| (id.clone(), *rel, *dist))
        .collect();
    ordered.sort_by(|a, b| (a.1, a.2, &a.0).cmp(&(b.1, b.2, &b.0)));
    let mut node_cap_omitted = 0usize;
    if ordered.len() > NODE_CAP {
        node_cap_omitted = ordered.len() - NODE_CAP;
        ordered.truncate(NODE_CAP);
    }
    let kept: HashSet<String> = ordered.iter().map(|(id, _, _)| id.clone()).collect();

    // Fanout receipts only for nodes that survived the cap, and only for
    // neighbours that also survived it: a neighbour cut by the node cap is
    // counted by the cap receipt, not double-counted as fan-out.
    for (node_id, omitted) in omitted_by_node {
        if !kept.contains(&node_id) {
            continue;
        }
        if omitted > 0 {
            walk.receipts.push(Receipt::FanoutCapped {
                node: node_id,
                omitted,
            });
        }
    }
    if node_cap_omitted > 0 {
        walk.receipts.push(Receipt::NodeCapReached {
            omitted: node_cap_omitted,
        });
    }
    // Receipt order is deterministic: fan-out receipts follow backbone
    // order above; not-examined receipts were pushed in frontier order;
    // re-sort those by (kind, folder id) for stability across frontier
    // orderings, keeping kind order (not-examined, fanout, cap).
    fn not_examined_folder(receipt: &Receipt) -> Option<&str> {
        match receipt {
            Receipt::BroadFolderNotExamined { folder_id }
            | Receipt::SystemContainerNotExamined { folder_id } => Some(folder_id),
            _ => None,
        }
    }
    fn not_examined_rank(receipt: &Receipt) -> u8 {
        match receipt {
            Receipt::BroadFolderNotExamined { .. } => 0,
            Receipt::SystemContainerNotExamined { .. } => 1,
            _ => 2,
        }
    }
    {
        let mut first: Vec<Receipt> = walk
            .receipts
            .iter()
            .filter(|r| not_examined_folder(r).is_some())
            .cloned()
            .collect();
        first.sort_by(|a, b| {
            (not_examined_rank(a), not_examined_folder(a))
                .cmp(&(not_examined_rank(b), not_examined_folder(b)))
        });
        let rest: Vec<Receipt> = walk
            .receipts
            .iter()
            .filter(|r| not_examined_folder(r).is_none())
            .cloned()
            .collect();
        first.extend(rest);
        walk.receipts = first;
    }

    // 7. Read display columns plus the standing pass's structural facts for
    // the visible, admitted nodes only. `archived` mirrors the tool-surface
    // fold: the facet's presence IS the archived state (restore unsets it).
    if !ordered.is_empty() {
        let ids_json = serde_json::to_string::<Vec<String>>(
            &ordered.iter().map(|(id, _, _)| id.clone()).collect(),
        )?;
        let rows = sqlx::query(
            "SELECT id, name, type AS type_, kind, maturity, lifecycle, home_id, \
                    COALESCE(last_activity_at, updated_at, created_at) AS recency, \
                    EXISTS (SELECT 1 FROM facet_values a \
                             WHERE a.record_id = records.id AND a.key = ?1) AS archived \
                FROM records \
               WHERE id IN (SELECT value FROM json_each(?2)) AND deleted_at IS NULL",
        )
        .bind(crate::schema::ARCHIVED_FACET_KEY)
        .bind(ids_json)
        .fetch_all(pool)
        .await?;
        let mut meta: HashMap<String, NodeMeta> = HashMap::new();
        for row in rows {
            meta.insert(
                row.try_get("id")?,
                NodeMeta {
                    name: row.try_get("name")?,
                    type_: row.try_get("type_")?,
                    kind: row
                        .try_get::<Option<String>, _>("kind")?
                        .unwrap_or_default(),
                    maturity: row.try_get("maturity")?,
                    lifecycle: row.try_get("lifecycle")?,
                    home_id: row.try_get("home_id")?,
                    archived: row.try_get::<i64, _>("archived")? != 0,
                    recency: row.try_get("recency")?,
                },
            );
        }
        for (id, relation, distance) in ordered {
            if let Some(facts) = meta.remove(&id) {
                let via = admission.get(&id).and_then(|(_, _, v)| v.clone());
                // A home the caller cannot View is not named, even as another
                // node's `home_id`: hidden homes appear nowhere in the output.
                let home_id = facts.home_id.filter(|h| visible.contains(h));
                walk.nodes.push(Node {
                    id,
                    name: facts.name,
                    type_: facts.type_,
                    kind: facts.kind,
                    relation,
                    distance,
                    via,
                    maturity: facts.maturity,
                    lifecycle: facts.lifecycle,
                    home_id,
                    archived: facts.archived,
                    recency: facts.recency,
                });
            }
        }
    }
    // Final order: (relation, distance, id). Nodes were pushed in that
    // order already; sort defensively so the guarantee holds regardless.
    walk.nodes
        .sort_by(|a, b| (a.relation, a.distance, &a.id).cmp(&(b.relation, b.distance, &b.id)));
    Ok(walk)
}

// ---- Sub-step 1b: standing, ranking, output (structure only, no body text).

/// Maturities the engine seeds. Anything else present on a record is kept
/// raw as [`Standing::Unclassified`], never mapped: the workspace really
/// contains `active`, `ratified`, `draft`, and `reviewed`.
const SEEDED_MATURITIES: [&str; 5] = [
    "exploratory",
    "candidate",
    "proposed",
    "decided",
    "superseded",
];

/// What a visible node IS, structurally. Precedence when several apply:
/// Superseded > Decided > Historical > ActiveWork > Proposal > Exploratory >
/// Unclassified > Evidence (see [`standing_for`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    Superseded { heads: Vec<String> },
    Decided,
    ActiveWork,
    Proposal,
    Exploratory,
    Historical,
    Evidence,
    Unclassified { raw_maturity: String },
}

/// Which signal produced the standing. `Text` exists for the later marker
/// slice and is never produced from structure alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Basis {
    Structure,
    Declared,
    Text,
}

/// Ranking tier. `ClaimToCheck` is reserved for the marker slice and no node
/// classifies into it yet. Enum order IS rank order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Class {
    Obligation,
    ClaimToCheck,
    ActiveWork,
    Proposal,
    Evidence,
}

/// One ranked briefing row.
#[derive(Debug, Clone)]
pub struct Item {
    pub node: Node,
    pub standing: Standing,
    pub basis: Basis,
    pub class: Class,
}

/// The ranked briefing: items plus the walk's receipts and bounds.
#[derive(Debug, Clone, Default)]
pub struct Briefing {
    pub items: Vec<Item>,
    pub receipts: Vec<Receipt>,
    pub bounds: BriefingBounds,
}

/// Standing plus basis for one node, in precedence order. `heads` are the
/// visible live incoming-`supersedes` sources (already filtered);
/// `selected` is an effective visible `Resolution kind:decision` selecting
/// it; `terminality` is the governed lifecycle terminality, if governed.
/// Basis follows the SOURCE: link/selects/terminality/archive are Structure,
/// author-set maturity is Declared. Evidence carries Structure: the absence
/// of marks is engine-observed state, not an author declaration.
fn standing_for(
    maturity: Option<&str>,
    terminality: Option<&str>,
    is_work_item: bool,
    archived: bool,
    heads: Vec<String>,
    selected: bool,
) -> (Standing, Basis) {
    if !heads.is_empty() {
        return (Standing::Superseded { heads }, Basis::Structure);
    }
    if maturity == Some("superseded") {
        return (Standing::Superseded { heads: Vec::new() }, Basis::Declared);
    }
    if selected {
        return (Standing::Decided, Basis::Structure);
    }
    if maturity == Some("decided") {
        return (Standing::Decided, Basis::Declared);
    }
    if archived || matches!(terminality, Some("terminal_positive" | "terminal_negative")) {
        return (Standing::Historical, Basis::Structure);
    }
    if is_work_item && terminality == Some("open") {
        return (Standing::ActiveWork, Basis::Structure);
    }
    if matches!(maturity, Some("proposed" | "candidate")) {
        return (Standing::Proposal, Basis::Declared);
    }
    if maturity == Some("exploratory") {
        return (Standing::Exploratory, Basis::Declared);
    }
    if let Some(raw) = maturity {
        debug_assert!(
            !SEEDED_MATURITIES.contains(&raw),
            "seeded maturity must map above, never Unclassified"
        );
        return (
            Standing::Unclassified {
                raw_maturity: raw.to_string(),
            },
            Basis::Declared,
        );
    }
    (Standing::Evidence, Basis::Structure)
}

/// Ranking tier for a standing. A superseded FOCAL node is an Obligation —
/// the walk was asked about it, and its replacement must be seen — while a
/// superseded non-focal node is Evidence: already-dead context.
fn classify(standing: &Standing, relation: Relation) -> Class {
    match standing {
        Standing::Decided => Class::Obligation,
        Standing::Superseded { .. } if relation == Relation::Focal => Class::Obligation,
        Standing::Superseded { .. } => Class::Evidence,
        Standing::ActiveWork => Class::ActiveWork,
        Standing::Proposal | Standing::Exploratory | Standing::Unclassified { .. } => {
            Class::Proposal
        }
        Standing::Evidence | Standing::Historical => Class::Evidence,
    }
}

/// THE entry point: walk the bounded authorised neighbourhood, then rank it
/// by standing. Rank is lexicographic: class, then basis (Structure before
/// Declared), then relation (Focal < Frame < neighbours) and distance, then
/// recency (`COALESCE(last_activity_at, updated_at, created_at)`, newest
/// first) as the FINAL tie-break, then id. Degree, link counts, and read
/// counts are NOT inputs. Deterministic: identical inputs, identical output.
///
/// [`assemble`] remains for walk-level use (nodes + receipts without ranks).
pub async fn assemble_briefing(db: &Db, caller: &Caller, purpose: &Purpose) -> Result<Briefing> {
    let walk = assemble(db, caller, purpose).await?;
    let pool = db.write_pool();
    if walk.nodes.is_empty() {
        return Ok(Briefing {
            items: Vec::new(),
            receipts: walk.receipts,
            bounds: walk.bounds,
        });
    }
    let ids_json =
        serde_json::to_string::<Vec<String>>(&walk.nodes.iter().map(|n| n.id.clone()).collect())?;

    // Incoming live `supersedes` sources per node. Heads join the visibility
    // pass: only heads the caller may View name the Superseded standing.
    let head_rows = sqlx::query(
        "SELECT l.target_id AS target, l.source_id AS head FROM links l \
           JOIN records s ON s.id = l.source_id \
          WHERE l.relationship = 'supersedes' AND s.deleted_at IS NULL \
            AND l.target_id IN (SELECT value FROM json_each(?)) \
          ORDER BY l.target_id, l.created_at, l.source_id",
    )
    .bind(&ids_json)
    .fetch_all(pool)
    .await?;
    let mut heads_of: HashMap<String, Vec<String>> = HashMap::new();
    for row in head_rows {
        heads_of
            .entry(row.try_get("target")?)
            .or_default()
            .push(row.try_get("head")?);
    }

    // Selecting decisions per node, newest first — the `selection_context_in`
    // query in `src/contribution.rs`, batched over the walk, PLUS the
    // brief's `kind = 'decision'` filter (the single-record helper does not
    // filter kind). Effectiveness is computed below in Rust over visible
    // LIVE superseders only: a hidden or deleted `supersedes` source must
    // not flip a selected node from Decided to Evidence. This matches
    // `selection_context_in`, which applies the same live-plus-visible
    // rule; only the `kind` filter differs, and the briefing must not leak
    // hidden records through a standing flip.
    let select_rows = sqlx::query(
        "SELECT l.target_id AS target, l.source_id AS decision \
            FROM links l JOIN records d ON d.id = l.source_id \
           WHERE l.relationship = 'selects' \
             AND d.type = 'Resolution' AND d.kind = 'decision' \
             AND d.deleted_at IS NULL \
             AND l.target_id IN (SELECT value FROM json_each(?)) \
           ORDER BY l.target_id, l.created_at DESC, l.source_id DESC",
    )
    .bind(&ids_json)
    .fetch_all(pool)
    .await?;
    let mut selects_of: HashMap<String, Vec<String>> = HashMap::new();
    for row in select_rows {
        selects_of
            .entry(row.try_get("target")?)
            .or_default()
            .push(row.try_get("decision")?);
    }

    // Candidate superseders per selecting decision. Live sources only
    // (`deleted_at IS NULL`); the visibility pass below decides which of
    // them the caller may see. A decision is effective when NO live
    // superseder visible to the caller survives.
    let mut supersedes_of: HashMap<String, Vec<String>> = HashMap::new();
    {
        let decisions: Vec<String> = selects_of
            .values()
            .flat_map(|decisions| decisions.iter().cloned())
            .collect();
        if !decisions.is_empty() {
            let decisions_json = serde_json::to_string(&decisions)?;
            let sup_rows = sqlx::query(
                "SELECT l.target_id AS decision, l.source_id AS superseder \
                    FROM links l JOIN records s ON s.id = l.source_id \
                   WHERE l.relationship = 'supersedes' AND s.deleted_at IS NULL \
                     AND l.target_id IN (SELECT value FROM json_each(?)) \
                   ORDER BY l.target_id, l.source_id",
            )
            .bind(&decisions_json)
            .fetch_all(pool)
            .await?;
            for row in sup_rows {
                supersedes_of
                    .entry(row.try_get("decision")?)
                    .or_default()
                    .push(row.try_get("superseder")?);
            }
        }
    }

    // Authorise the standing inputs that are not walk nodes. Walk nodes are
    // already visible; heads, decisions, and candidate superseders may lie
    // outside the walk.
    let mut extra: Vec<String> = Vec::new();
    for heads in heads_of.values() {
        extra.extend(heads.iter().cloned());
    }
    for selects in selects_of.values() {
        extra.extend(selects.iter().cloned());
    }
    for superseders in supersedes_of.values() {
        extra.extend(superseders.iter().cloned());
    }
    let extra_visible = if extra.is_empty() {
        HashSet::new()
    } else {
        visible_ids_in_pool(pool, caller, extra).await?
    };

    let principal = (!is_legacy_local(caller)).then(|| principal(caller));
    let interpreter = crate::query::lifecycle::LifecycleInterpreter::load(db, principal).await?;

    let mut items = Vec::with_capacity(walk.nodes.len());
    for node in walk.nodes {
        let heads: Vec<String> = heads_of
            .remove(&node.id)
            .unwrap_or_default()
            .into_iter()
            .filter(|id| extra_visible.contains(id))
            .collect();
        // First visible decision in newest-first order decides — mirroring
        // `selection_context_in`, which returns the first visible row rather
        // than falling through to an older decision. Its effectiveness is
        // recomputed here: effective unless a LIVE superseder VISIBLE to the
        // caller survives (hidden and deleted superseders are ignored).
        let mut selected = false;
        if let Some(selects) = selects_of.remove(&node.id) {
            for decision in selects {
                if extra_visible.contains(&decision) {
                    let superseded = supersedes_of
                        .get(&decision)
                        .map(|superseders| superseders.iter().any(|id| extra_visible.contains(id)))
                        .unwrap_or(false);
                    selected = !superseded;
                    break;
                }
            }
        }
        let terminality = match interpreter.interpret(
            &node.type_,
            (!node.kind.is_empty()).then_some(node.kind.as_str()),
            node.home_id.as_deref(),
            node.lifecycle.as_deref(),
        ) {
            crate::query::lifecycle::LifecycleInterpretation::Governed(governed) => {
                Some(governed.terminality)
            }
            _ => None,
        };
        let (standing, basis) = standing_for(
            node.maturity.as_deref(),
            terminality.as_deref(),
            node.type_ == "WorkItem",
            node.archived,
            heads,
            selected,
        );
        let class = classify(&standing, node.relation);
        items.push(Item {
            node,
            standing,
            basis,
            class,
        });
    }
    items.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then_with(|| a.basis.cmp(&b.basis))
            .then_with(|| a.node.relation.cmp(&b.node.relation))
            .then_with(|| a.node.distance.cmp(&b.node.distance))
            .then_with(|| b.node.recency.cmp(&a.node.recency))
            .then_with(|| a.node.id.cmp(&b.node.id))
    });
    Ok(Briefing {
        items,
        receipts: walk.receipts,
        bounds: walk.bounds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    use crate::authorization::{replace_explicit_policy, AllowEntry, Capability};
    use crate::db::create_database;
    use crate::events::LinkAddedPayload;
    use crate::mcp::ToolRegistry;
    use crate::schema::UNFILED_RECORD_ID;
    use crate::store::{add_link, create_record};

    fn alice() -> Caller {
        Caller::authenticated("alice")
    }

    fn bea() -> Caller {
        Caller::authenticated("bea")
    }

    async fn mk(db: &Db, id: &str, name: &str) {
        create_record(
            db,
            json!({"id": id, "type": "Document", "kind": "note", "name": name}),
        )
        .await
        .unwrap();
    }

    /// Filing folders must be Collection/folder: `record.created` rejects any
    /// other home (and a record cannot be its own home). Folders take the
    /// default home, whose cut is receipted; the fanout test counts the walk
    /// exactly.
    async fn mk_folder(db: &Db, id: &str, name: &str) {
        create_record(
            db,
            json!({"id": id, "type": "Collection", "kind": "folder", "name": name}),
        )
        .await
        .unwrap();
    }

    async fn grant(db: &Db, id: &str, accounts: &[&str]) {
        replace_explicit_policy(
            db,
            "test:policy",
            id,
            accounts
                .iter()
                .map(|a| AllowEntry::account(*a, Capability::View))
                .collect(),
        )
        .await
        .unwrap();
    }

    async fn link(db: &Db, id: &str, source: &str, target: &str, rel: &str) {
        add_link(
            db,
            LinkAddedPayload {
                id: Some(id.to_string()),
                source_id: source.to_string(),
                target_id: target.to_string(),
                relationship: rel.to_string(),
                note: None,
            },
        )
        .await
        .unwrap();
    }

    /// Records with explicit type/kind/maturity/lifecycle for standing tests.
    async fn mk_full(
        db: &Db,
        id: &str,
        typ: &str,
        kind: &str,
        name: &str,
        maturity: Option<&str>,
        lifecycle: Option<&str>,
    ) {
        let mut fields = json!({"id": id, "type": typ, "kind": kind, "name": name});
        if let Some(maturity) = maturity {
            fields["maturity"] = json!(maturity);
        }
        if let Some(lifecycle) = lifecycle {
            fields["lifecycle"] = json!(lifecycle);
        }
        create_record(db, fields).await.unwrap();
    }

    /// Relationship-owned edges (`selects`, `relates_to`, ...) only reach the
    /// `links` table via the production tool path, which writes the
    /// compatibility row while the assertion is effective.
    async fn tool_link(db: &Db, source: &str, target: &str, rel: &str) {
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_links",
                json!({"action": "add", "source_id": source,
                       "target_id": target, "relationship": rel}),
            )
            .await
            .unwrap();
    }

    fn purpose(focal: &[&str]) -> Purpose {
        Purpose {
            focal: focal.iter().map(|s| s.to_string()).collect(),
            as_of: None,
        }
    }

    /// Canonical v4 UUIDs for fixtures: `create_record` rejects anything else.
    fn u(n: u32) -> String {
        format!("7e5b{n:04}-0000-4000-8000-{n:012}")
    }

    fn node_ids(walk: &Walk) -> Vec<String> {
        walk.nodes.iter().map(|n| n.id.clone()).collect()
    }

    #[tokio::test]
    async fn shortlist_graph_yields_frame_and_frame_neighbours() {
        let db = create_database(":memory:").await.unwrap();
        let (f, t, d, c) = (u(1), u(2), u(3), u(4));
        for (id, name) in [(&f, "focal"), (&t, "topic"), (&d, "derived"), (&c, "cited")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(11), &f, &t, "part_of").await;
        link(&db, &u(12), &d, &t, "derived_from").await;
        link(&db, &u(13), &t, &c, "mentions").await;
        let walk = assemble(&db, &alice(), &purpose(&[&f])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[f.as_str()].relation, Relation::Focal);
        assert_eq!(by_id[f.as_str()].distance, 0);
        assert_eq!(by_id[t.as_str()].relation, Relation::Frame);
        assert_eq!(
            by_id[t.as_str()].via,
            Some(("part_of".to_string(), f.clone()))
        );
        assert_eq!(by_id[d.as_str()].relation, Relation::FrameNeighbour);
        assert_eq!(by_id[c.as_str()].relation, Relation::FrameNeighbour);
        // Default homes are system containers: unfiled is cut, never a frame.
        assert_eq!(
            walk.receipts,
            vec![Receipt::SystemContainerNotExamined {
                folder_id: UNFILED_RECORD_ID.to_string()
            }]
        );
    }

    #[tokio::test]
    async fn broad_folder_home_is_not_a_frame() {
        let db = create_database(":memory:").await.unwrap();
        let (folder, focal) = (u(21), u(22));
        mk_folder(&db, &folder, "big").await;
        grant(&db, &folder, &["alice"]).await;
        for i in 0..51u32 {
            let id = u(1000 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "kid", "home_id": folder}),
            )
            .await
            .unwrap();
        }
        create_record(
            &db,
            json!({"id": focal, "type": "Document", "kind": "note",
                   "name": "focal-big", "home_id": folder}),
        )
        .await
        .unwrap();
        grant(&db, &focal, &["alice"]).await;
        let walk = assemble(&db, &alice(), &purpose(&[&focal])).await.unwrap();
        assert!(!node_ids(&walk).contains(&folder));
        assert!(walk.receipts.contains(&Receipt::BroadFolderNotExamined {
            folder_id: folder.clone()
        }));
    }

    #[tokio::test]
    async fn fifty_visible_children_is_a_frame() {
        // B3 boundary: exactly BROAD_FOLDER_CHILDREN visible children
        // (49 kids + the focal itself) still frames the home.
        let db = create_database(":memory:").await.unwrap();
        let (folder, focal) = (u(6101), u(6102));
        mk_folder(&db, &folder, "edge").await;
        grant(&db, &folder, &["alice"]).await;
        for i in 0..49u32 {
            let id = u(6150 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "kid", "home_id": folder}),
            )
            .await
            .unwrap();
            grant(&db, &id, &["alice"]).await;
        }
        create_record(
            &db,
            json!({"id": focal, "type": "Document", "kind": "note",
                   "name": "focal-edge", "home_id": folder}),
        )
        .await
        .unwrap();
        grant(&db, &focal, &["alice"]).await;
        let walk = assemble(&db, &alice(), &purpose(&[&focal])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[folder.as_str()].relation, Relation::Frame);
        assert!(!walk
            .receipts
            .iter()
            .any(|r| matches!(r, Receipt::BroadFolderNotExamined { .. })));
    }

    #[tokio::test]
    async fn fifty_one_visible_children_is_broad() {
        // B3 boundary: one child past the threshold flips the home to a
        // not-examined receipt.
        let db = create_database(":memory:").await.unwrap();
        let (folder, focal) = (u(6201), u(6202));
        mk_folder(&db, &folder, "over").await;
        grant(&db, &folder, &["alice"]).await;
        for i in 0..50u32 {
            let id = u(6250 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "kid", "home_id": folder}),
            )
            .await
            .unwrap();
            grant(&db, &id, &["alice"]).await;
        }
        create_record(
            &db,
            json!({"id": focal, "type": "Document", "kind": "note",
                   "name": "focal-over", "home_id": folder}),
        )
        .await
        .unwrap();
        grant(&db, &focal, &["alice"]).await;
        let walk = assemble(&db, &alice(), &purpose(&[&focal])).await.unwrap();
        assert!(!node_ids(&walk).contains(&folder));
        assert!(walk.receipts.contains(&Receipt::BroadFolderNotExamined {
            folder_id: folder.clone()
        }));
    }

    #[tokio::test]
    async fn hidden_children_do_not_flip_the_broad_bit() {
        // B3 oracle: 50 visible children frame the home even with 5 extra
        // children the caller cannot see.
        let db = create_database(":memory:").await.unwrap();
        let (folder, focal) = (u(6301), u(6302));
        mk_folder(&db, &folder, "mixed").await;
        grant(&db, &folder, &["alice", "bea"]).await;
        for i in 0..49u32 {
            let id = u(6350 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "kid", "home_id": folder}),
            )
            .await
            .unwrap();
            grant(&db, &id, &["alice", "bea"]).await;
        }
        for i in 0..5u32 {
            let id = u(6400 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "hidden-kid", "home_id": folder}),
            )
            .await
            .unwrap();
            grant(&db, &id, &["alice"]).await;
        }
        create_record(
            &db,
            json!({"id": focal, "type": "Document", "kind": "note",
                   "name": "focal-mixed", "home_id": folder}),
        )
        .await
        .unwrap();
        grant(&db, &focal, &["alice", "bea"]).await;
        let walk = assemble(&db, &bea(), &purpose(&[&focal])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[folder.as_str()].relation, Relation::Frame);
        assert!(!walk
            .receipts
            .iter()
            .any(|r| matches!(r, Receipt::BroadFolderNotExamined { .. })));
    }

    #[tokio::test]
    async fn workitem_home_with_many_children_is_a_frame() {
        // The WorkItem-home-is-always-a-frame rule survives the broad
        // threshold: 51 visible children still frame the WorkItem home.
        // `record.created` only files under Collection/folder homes, so the
        // fixture files under the WorkItem with a direct update — the walk
        // reads the table, not the write path.
        let db = create_database(":memory:").await.unwrap();
        let (home, focal) = (u(6501), u(6502));
        mk_full(&db, &home, "WorkItem", "task", "work-home", None, None).await;
        grant(&db, &home, &["alice"]).await;
        let pool = db.write_pool();
        for i in 0..50u32 {
            let id = u(6550 + i);
            mk(&db, &id, "kid").await;
            grant(&db, &id, &["alice"]).await;
            sqlx::query("UPDATE records SET home_id = ?1 WHERE id = ?2")
                .bind(&home)
                .bind(&id)
                .execute(pool)
                .await
                .unwrap();
        }
        mk(&db, &focal, "focal-work").await;
        grant(&db, &focal, &["alice"]).await;
        sqlx::query("UPDATE records SET home_id = ?1 WHERE id = ?2")
            .bind(&home)
            .bind(&focal)
            .execute(pool)
            .await
            .unwrap();
        let walk = assemble(&db, &alice(), &purpose(&[&focal])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[home.as_str()].relation, Relation::Frame);
        assert_eq!(
            by_id[home.as_str()].via,
            Some(("home".to_string(), focal.clone()))
        );
    }
    #[tokio::test]
    async fn hidden_broad_home_yields_no_receipt_and_no_id() {
        // B1: a home the caller cannot View produces nothing — no node, no
        // receipt, and its id appears nowhere in the output.
        let db = create_database(":memory:").await.unwrap();
        let (folder, focal) = (u(5101), u(5102));
        mk_folder(&db, &folder, "hidden-big").await;
        grant(&db, &folder, &["alice"]).await;
        for i in 0..51u32 {
            let id = u(5200 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "kid", "home_id": folder}),
            )
            .await
            .unwrap();
            grant(&db, &id, &["alice"]).await;
        }
        create_record(
            &db,
            json!({"id": focal, "type": "Document", "kind": "note",
                   "name": "focal-hidden-home", "home_id": folder}),
        )
        .await
        .unwrap();
        grant(&db, &focal, &["alice", "bea"]).await;
        let walk = assemble(&db, &bea(), &purpose(&[&focal])).await.unwrap();
        assert!(!node_ids(&walk).contains(&folder));
        assert!(!walk.receipts.contains(&Receipt::BroadFolderNotExamined {
            folder_id: folder.clone()
        }));
        let dumped = format!("{:?}", walk);
        assert!(
            !dumped.contains(&folder),
            "hidden home id leaked into walk output"
        );
    }

    #[tokio::test]
    async fn small_collection_home_is_a_frame() {
        let db = create_database(":memory:").await.unwrap();
        let (folder, focal) = (u(31), u(32));
        mk_folder(&db, &folder, "small").await;
        grant(&db, &folder, &["alice"]).await;
        create_record(
            &db,
            json!({"id": focal, "type": "Document", "kind": "note",
                   "name": "focal-g", "home_id": folder}),
        )
        .await
        .unwrap();
        grant(&db, &focal, &["alice"]).await;
        let walk = assemble(&db, &alice(), &purpose(&[&focal])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[folder.as_str()].relation, Relation::Frame);
        assert_eq!(
            by_id[folder.as_str()].via,
            Some(("home".to_string(), focal.clone()))
        );
    }

    #[tokio::test]
    async fn hidden_neighbour_absent_from_nodes_receipts_counts() {
        let db = create_database(":memory:").await.unwrap();
        let (a, v, h) = (u(41), u(42), u(43));
        for (id, name) in [(&a, "anchor"), (&v, "visible"), (&h, "hidden")] {
            mk(&db, id, name).await;
        }
        grant(&db, &a, &["alice", "bea"]).await;
        grant(&db, &v, &["alice", "bea"]).await;
        grant(&db, &h, &["alice"]).await;
        link(&db, &u(44), &a, &v, "mentions").await;
        link(&db, &u(45), &a, &h, "mentions").await;
        let walk = assemble(&db, &bea(), &purpose(&[&a])).await.unwrap();
        let ids = node_ids(&walk);
        assert!(ids.contains(&a));
        assert!(ids.contains(&v));
        assert!(!ids.contains(&h));
        // The only receipt is the cut system home: nothing may name, count,
        // or imply the hidden record.
        assert_eq!(
            walk.receipts,
            vec![Receipt::SystemContainerNotExamined {
                folder_id: UNFILED_RECORD_ID.to_string()
            }]
        );
        let dumped = format!("{:?}", walk);
        assert!(!dumped.contains(&h));
    }

    #[tokio::test]
    async fn hidden_neighbours_do_not_consume_fanout() {
        // S9 pressure: 5 hidden neighbours sort FIRST (smaller ids) ahead
        // of 12 visible ones on one node. Hidden candidates consume no
        // fan-out slots: all 12 visible survive, nothing is omitted, and no
        // receipt names a hidden record.
        let db = create_database(":memory:").await.unwrap();
        let a = u(7501);
        mk(&db, &a, "anchor").await;
        grant(&db, &a, &["alice", "bea"]).await;
        for i in 0..5u32 {
            let id = u(7510 + i);
            mk(&db, &id, "hidden").await;
            grant(&db, &id, &["alice"]).await;
            link(&db, &u(7600 + i), &a, &id, "mentions").await;
        }
        for i in 0..12u32 {
            let id = u(7550 + i);
            mk(&db, &id, "visible").await;
            grant(&db, &id, &["alice", "bea"]).await;
            link(&db, &u(7700 + i), &a, &id, "mentions").await;
        }
        let walk = assemble(&db, &bea(), &purpose(&[&a])).await.unwrap();
        let ids = node_ids(&walk);
        assert_eq!(ids.len(), 13);
        for i in 0..12u32 {
            let id = u(7550 + i);
            assert!(ids.contains(&id), "visible neighbour {id} lost a slot");
        }
        for i in 0..5u32 {
            let id = u(7510 + i);
            assert!(!ids.contains(&id), "hidden neighbour {id} admitted");
        }
        assert!(
            !walk
                .receipts
                .iter()
                .any(|r| matches!(r, Receipt::FanoutCapped { .. })),
            "no neighbour cut, so no fan-out receipt: {:?}",
            walk.receipts
        );
        let dumped = format!("{:?}", walk);
        for i in 0..5u32 {
            let id = u(7510 + i);
            assert!(!dumped.contains(&id), "hidden neighbour {id} leaked");
        }
    }

    #[tokio::test]
    async fn fanout_cap_cuts_frame_neighbours_with_receipt() {
        let db = create_database(":memory:").await.unwrap();
        let (f, t, h) = (u(51), u(52), u(53));
        // One folder for every record: the frame chain runs f -> h and stops
        // at the cut system home, so the exact node count below is
        // fixture-determined (focal + frame + folder + 12 capped neighbours).
        mk_folder(&db, &h, "home").await;
        grant(&db, &h, &["alice"]).await;
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": name, "home_id": h}),
            )
            .await
            .unwrap();
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(54), &f, &t, "part_of").await;
        for i in 0..15u32 {
            let id = u(2000 + i);
            create_record(
                &db,
                json!({"id": id, "type": "Document", "kind": "note",
                       "name": "neighbour", "home_id": h}),
            )
            .await
            .unwrap();
            grant(&db, &id, &["alice"]).await;
            link(&db, &u(3000 + i), &t, &id, "mentions").await;
        }
        let walk = assemble(&db, &alice(), &purpose(&[&f])).await.unwrap();
        // Focal + frame + home folder + 12 capped neighbours. The folder's
        // own home (unfiled) is cut, never a fifth frame.
        assert_eq!(walk.nodes.len(), 15);
        assert!(walk.receipts.contains(&Receipt::FanoutCapped {
            node: t.clone(),
            omitted: 3
        }));
        assert!(walk
            .receipts
            .contains(&Receipt::SystemContainerNotExamined {
                folder_id: UNFILED_RECORD_ID.to_string()
            }));
    }

    #[tokio::test]
    async fn fanout_prefers_frame_edges_then_id_order() {
        // S1+S2: the fan-out cut is (frame-type first, relationship ASC,
        // neighbour id ASC, link id ASC) with no recency input. Frame node
        // `t` has 2 frame-type neighbours (incoming, so they never become
        // frame parents) plus 15 `mentions` neighbours: the 2 frame edges
        // plus the 10 smallest mentions ids survive, 5 omitted.
        // (`implements` would be a third frame-type edge, but it is
        // relationship-owned: only `part_of`/`derived_from` reach the links
        // table through the raw test helper.)
        let db = create_database(":memory:").await.unwrap();
        let (f, t) = (u(6901), u(6902));
        let (x_derived, x_part) = (u(6903), u(6905));
        for (id, name) in [
            (&f, "focal"),
            (&t, "topic"),
            (&x_derived, "derived"),
            (&x_part, "part"),
        ] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(6911), &f, &t, "part_of").await;
        link(&db, &u(6912), &x_derived, &t, "derived_from").await;
        link(&db, &u(6914), &x_part, &t, "part_of").await;
        for i in 0..15u32 {
            let id = u(7000 + i);
            mk(&db, &id, "neighbour").await;
            grant(&db, &id, &["alice"]).await;
            link(&db, &u(7100 + i), &t, &id, "mentions").await;
        }
        let walk = assemble(&db, &alice(), &purpose(&[&f])).await.unwrap();
        let ids = node_ids(&walk);
        for id in [&x_derived, &x_part] {
            assert!(ids.contains(id), "frame edge {id} cut by fan-out");
        }
        for i in 0..10u32 {
            let id = u(7000 + i);
            assert!(ids.contains(&id), "mentions neighbour {id} wrongly cut");
        }
        for i in 10..15u32 {
            let id = u(7000 + i);
            assert!(!ids.contains(&id), "mentions neighbour {id} wrongly kept");
        }
        assert!(walk.receipts.contains(&Receipt::FanoutCapped {
            node: t.clone(),
            omitted: 5
        }));
    }

    #[tokio::test]
    async fn superseding_head_also_focal() {
        let db = create_database(":memory:").await.unwrap();
        let (x, y) = (u(61), u(62));
        mk(&db, &x, "old").await;
        grant(&db, &x, &["alice"]).await;
        mk(&db, &y, "head").await;
        grant(&db, &y, &["alice"]).await;
        link(&db, &u(63), &y, &x, "supersedes").await;
        let walk = assemble(&db, &alice(), &purpose(&[&x])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[x.as_str()].relation, Relation::Focal);
        assert_eq!(by_id[y.as_str()].relation, Relation::Focal);
    }

    #[tokio::test]
    async fn two_runs_give_identical_output() {
        let db = create_database(":memory:").await.unwrap();
        let (f, t, d, c) = (u(71), u(72), u(73), u(74));
        for (id, name) in [(&f, "focal"), (&t, "topic"), (&d, "derived"), (&c, "cited")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(75), &f, &t, "part_of").await;
        link(&db, &u(76), &d, &t, "derived_from").await;
        link(&db, &u(77), &t, &c, "mentions").await;
        let first = assemble(&db, &alice(), &purpose(&[&f])).await.unwrap();
        let second = assemble(&db, &alice(), &purpose(&[&f])).await.unwrap();
        let shape = |w: &Walk| {
            (
                w.nodes
                    .iter()
                    .map(|n| {
                        (
                            n.id.clone(),
                            n.relation,
                            n.distance,
                            n.via.clone(),
                            n.name.clone(),
                        )
                    })
                    .collect::<Vec<_>>(),
                w.receipts.clone(),
            )
        };
        assert_eq!(shape(&first), shape(&second));
        // And the shape itself is pinned exactly: node order is (relation,
        // distance, id), with the single not-examined receipt for the
        // default system home.
        assert_eq!(
            first.nodes.iter().map(|n| n.id.clone()).collect::<Vec<_>>(),
            vec![f.clone(), t.clone(), d.clone(), c.clone()]
        );
        assert_eq!(
            first.receipts,
            vec![Receipt::SystemContainerNotExamined {
                folder_id: UNFILED_RECORD_ID.to_string()
            }]
        );
    }

    #[tokio::test]
    async fn hidden_superseding_head_filtered_silently() {
        // S9 boundary: a hidden superseding head joins neither the walk nor
        // the standing — the focal node stays plain Evidence with no trace
        // of the head anywhere in the output.
        let db = create_database(":memory:").await.unwrap();
        let (x, y) = (u(7801), u(7802));
        mk(&db, &x, "old").await;
        grant(&db, &x, &["alice", "bea"]).await;
        mk(&db, &y, "hidden-head").await;
        grant(&db, &y, &["alice"]).await;
        link(&db, &u(7803), &y, &x, "supersedes").await;
        let walk = assemble(&db, &bea(), &purpose(&[&x])).await.unwrap();
        assert_eq!(node_ids(&walk), vec![x.clone()]);
        let dumped = format!("{:?}", walk);
        assert!(!dumped.contains(&y), "hidden head {y} leaked into walk");
        let briefing = assemble_briefing(&db, &bea(), &purpose(&[&x]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &x).standing, Standing::Evidence);
        assert!(!briefing
            .items
            .iter()
            .any(|item| matches!(item.standing, Standing::Superseded { .. })));
    }

    #[tokio::test]
    async fn deleted_link_targets_excluded_from_every_leg() {
        // S9 boundary: a deleted record leaves the frame leg and the
        // neighbourhood leg alike.
        let db = create_database(":memory:").await.unwrap();
        let (f, b, c) = (u(7901), u(7902), u(7903));
        for (id, name) in [(&f, "focal"), (&b, "dead-frame"), (&c, "neighbour")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(7911), &f, &b, "part_of").await;
        link(&db, &u(7912), &f, &c, "mentions").await;
        crate::store::delete_record(&db, &b).await.unwrap();
        let walk = assemble(&db, &alice(), &purpose(&[&f])).await.unwrap();
        let ids = node_ids(&walk);
        assert!(!ids.contains(&b), "deleted frame target admitted");
        assert!(ids.contains(&c), "live neighbour lost");
        let dumped = format!("{:?}", walk);
        assert!(!dumped.contains(&b), "deleted record {b} leaked into walk");
    }

    #[tokio::test]
    async fn governed_relates_to_asserted_through_tool_is_a_neighbour() {
        // `relates_to` is relationship-owned: a raw `link.added` event never
        // reaches the `links` table. Asserted through the production tool
        // path, the relationship projector writes a compatibility row
        // (`rel:{origin}:{relationship_id}`) while the assertion is
        // effective, and the walk admits the counterpart as a neighbour.
        let db = create_database(":memory:").await.unwrap();
        let (a, b) = (u(81), u(82));
        for (id, name) in [(&a, "anchor"), (&b, "other")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        tool_link(&db, &a, &b, "relates_to").await;
        let walk = assemble(&db, &alice(), &purpose(&[&a])).await.unwrap();
        let by_id: HashMap<&str, &Node> = walk.nodes.iter().map(|n| (n.id.as_str(), n)).collect();
        assert_eq!(by_id[b.as_str()].relation, Relation::FocalNeighbour);
        // Retract through the same tool: the compatibility row is deleted and
        // the counterpart leaves the walk.
        let mut registry = ToolRegistry::new();
        crate::mcp::register_surface_tools(&mut registry).unwrap();
        registry
            .call(
                db.clone(),
                Caller::local(),
                "manage_links",
                json!({"action": "remove", "source_id": a, "target_id": b,
                       "relationship": "relates_to"}),
            )
            .await
            .unwrap();
        let after = assemble(&db, &alice(), &purpose(&[&a])).await.unwrap();
        assert!(!node_ids(&after).contains(&b));
    }

    fn item_by<'x>(briefing: &'x Briefing, id: &str) -> &'x Item {
        briefing
            .items
            .iter()
            .find(|item| item.node.id == id)
            .unwrap()
    }

    fn item_ids(briefing: &Briefing) -> Vec<String> {
        briefing
            .items
            .iter()
            .map(|item| item.node.id.clone())
            .collect()
    }

    async fn sleep_a_tick() {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    #[tokio::test]
    async fn recent_exploratory_ranks_below_older_decided() {
        // Recency is the FINAL tie-break: it never overrides class. E is
        // strictly newer than D, yet the older decided record ranks first.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, d, e) = (u(4101), u(4102), u(4103), u(4104));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(4111), &f, &t, "part_of").await;
        mk_full(
            &db,
            &d,
            "Document",
            "note",
            "decided-old",
            Some("decided"),
            None,
        )
        .await;
        grant(&db, &d, &["alice"]).await;
        link(&db, &u(4112), &d, &t, "mentions").await;
        sleep_a_tick().await;
        mk_full(
            &db,
            &e,
            "Document",
            "note",
            "exploratory-new",
            Some("exploratory"),
            None,
        )
        .await;
        grant(&db, &e, &["alice"]).await;
        link(&db, &u(4113), &t, &e, "mentions").await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        assert_eq!(
            item_ids(&briefing),
            vec![d.clone(), e.clone(), f.clone(), t.clone()]
        );
        assert_eq!(item_by(&briefing, &d).standing, Standing::Decided);
        assert_eq!(item_by(&briefing, &d).class, Class::Obligation);
        assert_eq!(item_by(&briefing, &e).standing, Standing::Exploratory);
        assert_eq!(item_by(&briefing, &e).class, Class::Proposal);
    }

    #[tokio::test]
    async fn relates_to_does_not_supersede() {
        // Only an incoming `supersedes` edge supersedes. A newer record that
        // merely `relates_to` the decided record leaves it Decided.
        let db = create_database(":memory:").await.unwrap();
        let (r, n) = (u(4201), u(4202));
        mk_full(
            &db,
            &r,
            "Document",
            "note",
            "decided",
            Some("decided"),
            None,
        )
        .await;
        grant(&db, &r, &["alice"]).await;
        sleep_a_tick().await;
        mk(&db, &n, "newer").await;
        grant(&db, &n, &["alice"]).await;
        tool_link(&db, &n, &r, "relates_to").await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&r]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &r).standing, Standing::Decided);
        assert_eq!(item_by(&briefing, &r).class, Class::Obligation);
        assert_eq!(item_ids(&briefing)[0], r);
        assert!(!briefing
            .items
            .iter()
            .any(|item| matches!(item.standing, Standing::Superseded { .. })));
    }

    #[tokio::test]
    async fn structural_decision_outranks_declared() {
        // Same class (Obligation), same relation and distance — but S is
        // Decided by structure (effective selects) and M only by declaration.
        // M is strictly NEWER, so S first proves basis outranks recency.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, s, m, dec) = (u(4301), u(4302), u(4303), u(4304), u(4305));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(4311), &f, &t, "part_of").await;
        mk(&db, &s, "selected").await;
        grant(&db, &s, &["alice"]).await;
        mk_full(
            &db,
            &dec,
            "Resolution",
            "decision",
            "the-decision",
            None,
            None,
        )
        .await;
        grant(&db, &dec, &["alice"]).await;
        tool_link(&db, &dec, &s, "selects").await;
        link(&db, &u(4312), &t, &s, "mentions").await;
        sleep_a_tick().await;
        mk_full(
            &db,
            &m,
            "Document",
            "note",
            "declared-newer",
            Some("decided"),
            None,
        )
        .await;
        grant(&db, &m, &["alice"]).await;
        link(&db, &u(4313), &t, &m, "mentions").await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        let obligations: Vec<String> = briefing
            .items
            .iter()
            .filter(|item| item.class == Class::Obligation)
            .map(|item| item.node.id.clone())
            .collect();
        assert_eq!(obligations, vec![s.clone(), m.clone()]);
        assert_eq!(item_by(&briefing, &s).basis, Basis::Structure);
        assert_eq!(item_by(&briefing, &m).basis, Basis::Declared);
    }

    #[tokio::test]
    async fn superseded_decision_is_not_effective() {
        // The decision selecting S is itself superseded, so the structural
        // Decided route is dead and S stays Evidence.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, s, dec, x) = (u(4401), u(4402), u(4403), u(4404), u(4405));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(4411), &f, &t, "part_of").await;
        mk(&db, &s, "selected").await;
        grant(&db, &s, &["alice"]).await;
        link(&db, &u(4412), &t, &s, "mentions").await;
        mk_full(
            &db,
            &dec,
            "Resolution",
            "decision",
            "dead-decision",
            None,
            None,
        )
        .await;
        grant(&db, &dec, &["alice"]).await;
        tool_link(&db, &dec, &s, "selects").await;
        mk(&db, &x, "head").await;
        grant(&db, &x, &["alice"]).await;
        link(&db, &u(4413), &x, &dec, "supersedes").await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &s).standing, Standing::Evidence);
        assert_eq!(item_by(&briefing, &s).class, Class::Evidence);
    }

    #[tokio::test]
    async fn hidden_superseder_leaves_decision_effective() {
        // B2: a superseder the caller cannot View must not flip the selected
        // node from Decided to Evidence — and must not leak into the output.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, s, dec, x) = (u(5401), u(5402), u(5403), u(5404), u(5405));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice", "bea"]).await;
        }
        link(&db, &u(5411), &f, &t, "part_of").await;
        mk(&db, &s, "selected").await;
        grant(&db, &s, &["alice", "bea"]).await;
        link(&db, &u(5412), &t, &s, "mentions").await;
        mk_full(
            &db,
            &dec,
            "Resolution",
            "decision",
            "live-decision",
            None,
            None,
        )
        .await;
        grant(&db, &dec, &["alice", "bea"]).await;
        tool_link(&db, &dec, &s, "selects").await;
        mk(&db, &x, "hidden-head").await;
        grant(&db, &x, &["alice"]).await;
        link(&db, &u(5413), &x, &dec, "supersedes").await;
        let briefing = assemble_briefing(&db, &bea(), &purpose(&[&f]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &s).standing, Standing::Decided);
        assert_eq!(item_by(&briefing, &s).class, Class::Obligation);
        let dumped = format!("{:?}", briefing.items);
        assert!(
            !dumped.contains(&x),
            "hidden superseder leaked into briefing output"
        );
    }

    #[tokio::test]
    async fn deleted_superseder_leaves_decision_effective() {
        // B2: a deleted superseder is dead everywhere — the selected node
        // stays Decided.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, s, dec, x) = (u(5501), u(5502), u(5503), u(5504), u(5505));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(5511), &f, &t, "part_of").await;
        mk(&db, &s, "selected").await;
        grant(&db, &s, &["alice"]).await;
        link(&db, &u(5512), &t, &s, "mentions").await;
        mk_full(
            &db,
            &dec,
            "Resolution",
            "decision",
            "live-decision",
            None,
            None,
        )
        .await;
        grant(&db, &dec, &["alice"]).await;
        tool_link(&db, &dec, &s, "selects").await;
        mk(&db, &x, "dead-head").await;
        grant(&db, &x, &["alice"]).await;
        link(&db, &u(5513), &x, &dec, "supersedes").await;
        crate::store::delete_record(&db, &x).await.unwrap();
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &s).standing, Standing::Decided);
        assert_eq!(item_by(&briefing, &s).class, Class::Obligation);
    }

    #[tokio::test]
    async fn open_work_item_is_active_work() {
        // S8: a plain `in_progress` WorkItem — unarchived, unterminated —
        // is ActiveWork by structure. This pins that `in_progress` means
        // open work, not history: only terminal lifecycles (like
        // `completed`) and archiving historicise a task.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, w) = (u(7401), u(7402), u(7403));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(7411), &f, &t, "part_of").await;
        mk_full(
            &db,
            &w,
            "WorkItem",
            "task",
            "open-task",
            None,
            Some("in_progress"),
        )
        .await;
        grant(&db, &w, &["alice"]).await;
        link(&db, &u(7412), &t, &w, "mentions").await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &w).standing, Standing::ActiveWork);
        assert_eq!(item_by(&briefing, &w).basis, Basis::Structure);
        assert_eq!(item_by(&briefing, &w).class, Class::ActiveWork);
    }

    #[tokio::test]
    async fn terminal_task_is_historical() {
        // Terminal lifecycle and archiving are both structural Historical —
        // even an otherwise-open WorkItem, once archived.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, w1, w2) = (u(4501), u(4502), u(4503), u(4504));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(4511), &f, &t, "part_of").await;
        mk_full(
            &db,
            &w1,
            "WorkItem",
            "task",
            "done-task",
            None,
            Some("completed"),
        )
        .await;
        grant(&db, &w1, &["alice"]).await;
        link(&db, &u(4512), &t, &w1, "mentions").await;
        mk_full(
            &db,
            &w2,
            "WorkItem",
            "task",
            "archived-task",
            None,
            Some("in_progress"),
        )
        .await;
        grant(&db, &w2, &["alice"]).await;
        link(&db, &u(4513), &t, &w2, "mentions").await;
        crate::store::archive_record(&db, &w2).await.unwrap();
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        assert_eq!(item_by(&briefing, &w1).standing, Standing::Historical);
        assert_eq!(item_by(&briefing, &w1).basis, Basis::Structure);
        assert_eq!(item_by(&briefing, &w2).standing, Standing::Historical);
        assert_eq!(item_by(&briefing, &w2).basis, Basis::Structure);
    }

    #[tokio::test]
    async fn unknown_maturity_is_unclassified_with_raw_value() {
        // `active` is a real workspace maturity but not a seeded one: kept
        // raw, never mapped, ranked as Proposal.
        let db = create_database(":memory:").await.unwrap();
        let a = u(4601);
        mk_full(
            &db,
            &a,
            "Document",
            "note",
            "active-doc",
            Some("active"),
            None,
        )
        .await;
        grant(&db, &a, &["alice"]).await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&a]))
            .await
            .unwrap();
        assert_eq!(
            item_by(&briefing, &a).standing,
            Standing::Unclassified {
                raw_maturity: "active".to_string()
            }
        );
        assert_eq!(item_by(&briefing, &a).basis, Basis::Declared);
        assert_eq!(item_by(&briefing, &a).class, Class::Proposal);
    }

    #[tokio::test]
    async fn focal_neighbour_sorts_before_frame_neighbour() {
        // S4: at equal class and basis, the focal's own neighbour (distance
        // 1) precedes a frame neighbour (distance 2) — even when the frame
        // neighbour is strictly newer and recency favours it.
        let db = create_database(":memory:").await.unwrap();
        let (f, t, n, m) = (u(7301), u(7302), u(7303), u(7304));
        for (id, name) in [(&f, "focal"), (&t, "topic")] {
            mk(&db, id, name).await;
            grant(&db, id, &["alice"]).await;
        }
        link(&db, &u(7311), &f, &t, "part_of").await;
        mk(&db, &n, "older-own").await;
        grant(&db, &n, &["alice"]).await;
        link(&db, &u(7312), &f, &n, "mentions").await;
        sleep_a_tick().await;
        mk(&db, &m, "newer-frame").await;
        grant(&db, &m, &["alice"]).await;
        link(&db, &u(7313), &t, &m, "mentions").await;
        let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
            .await
            .unwrap();
        for id in [&f, &t, &n, &m] {
            assert_eq!(item_by(&briefing, id).standing, Standing::Evidence);
        }
        assert_eq!(
            item_ids(&briefing),
            vec![f.clone(), t.clone(), n.clone(), m.clone()]
        );
    }

    #[tokio::test]
    async fn recency_only_breaks_ties() {
        // Two otherwise-identical Evidence neighbours: newer first, and
        // swapping creation order swaps the order with nothing else changed.
        let (f, t, a, b) = (u(4701), u(4702), u(4703), u(4704));
        for (first, second) in [(&a, &b), (&b, &a)] {
            let db = create_database(":memory:").await.unwrap();
            for (id, name) in [(&f, "focal"), (&t, "topic")] {
                mk(&db, id, name).await;
                grant(&db, id, &["alice"]).await;
            }
            link(&db, &u(4711), &f, &t, "part_of").await;
            mk(&db, first.as_str(), "first").await;
            grant(&db, first.as_str(), &["alice"]).await;
            link(&db, &u(4712), &t, first.as_str(), "mentions").await;
            sleep_a_tick().await;
            mk(&db, second.as_str(), "second").await;
            grant(&db, second.as_str(), &["alice"]).await;
            link(&db, &u(4713), &t, second.as_str(), "mentions").await;
            let briefing = assemble_briefing(&db, &alice(), &purpose(&[&f]))
                .await
                .unwrap();
            let pair: Vec<String> = item_ids(&briefing)
                .into_iter()
                .filter(|id| id == &a || id == &b)
                .collect();
            assert_eq!(pair, vec![second.clone(), first.clone()]);
            for item in &briefing.items {
                assert_eq!(item.standing, Standing::Evidence);
                assert_eq!(item.basis, Basis::Structure);
                assert_eq!(item.class, Class::Evidence);
            }
        }
    }
}
