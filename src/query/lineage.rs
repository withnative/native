//! The lineage walk — `run_key -> parent_key -> …`, resolved at read time
//! (spec fbfaf25 §5.3).
//!
//! Not a tool at v1, and deliberately so: the read-time contracts are specified
//! because they are what the columns are FOR, and two of them carry tests. This
//! is one of the two.
//!
//! ## The one thing that must not be omitted
//!
//! `parent_key` is an UNVERIFIED assertion by a child about its parent — there is
//! no issuance registry to check it against, and there is deliberately not going
//! to be one. So the graph a caller describes can cycle: A claims B, B claims A.
//! A naive walk hangs.
//!
//! It is the cheapest thing to omit and the worst to omit, because omitting it
//! produces a HANG rather than a wrong answer, and a hang is the worse failure —
//! a wrong answer is visible and correctable, a hung read is neither. So the walk
//! carries a depth cap AND cycle detection, and returns a **truncated path**
//! rather than an error. Truncated and unrooted runs are ordinary members of the
//! down-weightable tier the design already defines; they do not need a second
//! mechanism, and turning truncation into an error would invent one.
//!
//! ## Why an assertion is trusted at all
//!
//! CE has no adversary: one user, one credential, one `.db`. A wrong parent claim
//! is a confused display, not a breach. That reasoning is local to this edition
//! and explicitly does not transfer to a multi-tenant server.
//!
//! ## Where a parent claim is read from
//!
//! `content_events` is the permanent tier and is consulted first. A run that only
//! ever READ, though, wrote no content event, so its assertion exists only in
//! `read_log_calls` — which is disposable. The read-log lookup is therefore
//! fail-open in the strict sense: if the table has been dropped, the walk loses
//! resolution and returns a shorter path. It never errors, and it never becomes
//! the reason a caller's read fails.

use std::collections::HashSet;

use sqlx::Row;

use crate::db::Db;
use crate::error::Result;

/// The depth cap. Generous relative to any real delegation chain — the cap is a
/// backstop against pathological input, not a modelling statement about how deep
/// legitimate lineage goes, so it should not be tuned down to "what we expect".
pub const MAX_LINEAGE_DEPTH: usize = 32;

/// How a walk finished. Which of these it is matters to a reader deciding how
/// much to trust the path, so it is reported rather than collapsed into a bool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageEnd {
    /// A run with no asserted parent — the path is complete.
    Rooted,
    /// A key already on the path was reached again. The path is truncated at the
    /// point the cycle closed.
    Cycle,
    /// [`MAX_LINEAGE_DEPTH`] links were followed without reaching a root.
    DepthCap,
}

/// A resolved lineage: the path walked, and how it ended.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Lineage {
    /// The keys walked, starting with the key asked about.
    pub path: Vec<String>,
    /// True unless the walk reached a genuine root.
    pub truncated: bool,
    pub end: LineageEnd,
}

/// Resolve the parent a run asserted, if any.
///
/// The permanent tier wins. The read log is consulted only as a fallback, and
/// only if it is still there.
async fn asserted_parent(db: &Db, run_key: &str) -> Result<Option<String>> {
    let from_events = sqlx::query(
        "SELECT parent_key FROM content_events
          WHERE run_key = ? AND parent_key IS NOT NULL
          ORDER BY seq LIMIT 1",
    )
    .bind(run_key)
    .fetch_optional(db.write_pool())
    .await?;
    if let Some(row) = from_events {
        return Ok(row.try_get::<Option<String>, _>("parent_key")?);
    }

    // Fail-open: a dropped read log costs resolution, never the call.
    let from_read_log = sqlx::query(
        "SELECT parent_key FROM read_log_calls
          WHERE run_key = ? AND parent_key IS NOT NULL
          ORDER BY seq LIMIT 1",
    )
    .bind(run_key)
    .fetch_optional(db.write_pool())
    .await;
    match from_read_log {
        Ok(Some(row)) => Ok(row.try_get::<Option<String>, _>("parent_key")?),
        Ok(None) => Ok(None),
        Err(_) => Ok(None),
    }
}

/// Walk `run_key -> parent_key -> …` to a root, a cycle, or the depth cap.
///
/// Terminates on every input, including a mutually-asserting pair, and returns
/// promptly — the cycle is caught the first time a key repeats, not after the cap
/// grinds through 32 hops.
pub async fn lineage_walk(db: &Db, run_key: &str) -> Result<Lineage> {
    let mut path = vec![run_key.to_string()];
    let mut seen: HashSet<String> = HashSet::from([run_key.to_string()]);
    let mut current = run_key.to_string();

    loop {
        let Some(parent) = asserted_parent(db, &current).await? else {
            return Ok(Lineage {
                path,
                truncated: false,
                end: LineageEnd::Rooted,
            });
        };
        // Cycle detection BEFORE the push, so the repeated key does not appear
        // twice in a path the caller may render.
        if seen.contains(&parent) {
            return Ok(Lineage {
                path,
                truncated: true,
                end: LineageEnd::Cycle,
            });
        }
        if path.len() >= MAX_LINEAGE_DEPTH {
            return Ok(Lineage {
                path,
                truncated: true,
                end: LineageEnd::DepthCap,
            });
        }
        seen.insert(parent.clone());
        path.push(parent.clone());
        current = parent;
    }
}
