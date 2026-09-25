//! The honest-absence read-surface contract (`docs/honest-absence-contract.md`,
//! task a42f6e3, obligation 3 of decision 3854595).
//!
//! A replica holds a projection folded to frontier W plus the canonical events
//! W→F. Every read below W must answer *not held here* rather than *absent*,
//! because an agent handed an empty result concludes the thing does not exist
//! and then acts on that.
//!
//! Two properties of this module are load-bearing:
//!
//! * **Holding is observed, not declared.** [`HoldingDisclosure::observe`]
//!   reads what the log actually contains rather than a configured policy
//!   value. A declaration can drift from the data; `MIN(act)` cannot. It is
//!   also exactly the observable compaction moves, so the disclosure stays
//!   true across a mechanism that does not exist yet.
//! * **It is inert at window = ∞,** which is what ships. A database holding
//!   its log from genesis observes [`ActRange::from`] `= None`, every guard
//!   below passes unconditionally, and no surface can produce a `not_held`
//!   answer. That is asserted by test rather than by reading the code.
//!
//! The disclosure is an **act range**, per 3854595 and acd735f: the act is
//! allocated once per write transaction, so an act range can state "every
//! write in this span is held whole", which a set of per-domain `seq`
//! coordinates cannot.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};

pub const HOLDING_CONTRACT: &str = "native.holding-disclosure.v1";

/// The act range a replica holds. `from: None` means genesis — the whole log
/// is held and the honest-absence contract is vacuous on this replica.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ActRange {
    /// Oldest act held, or `None` for genesis. Never `Some(_)` on a database
    /// that still holds pre-cutover rows: those predate the act number
    /// entirely, so the log necessarily reaches back further than any act.
    pub from: Option<i64>,
    /// Newest act held. `0` on a database that has never been written.
    pub through: i64,
}

/// The declared history window. Derived from [`ActRange`] rather than
/// configured: a window is not a setting a replica can be wrong about, it is
/// the shape of what the replica has.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldingWindow {
    /// The log reaches genesis. What ships.
    Infinity,
    /// The log begins at `from_act`; everything below it has been compacted
    /// into the base projection.
    RetainedActs { from_act: i64 },
}

/// What a read below the window is told. Absent at window = ∞, because there
/// is nothing below the window to describe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BelowWindow {
    /// Held by the authority, not by this replica.
    NotHeld,
    /// Below acd735f's act cutover: the events are held, but which of them
    /// shared a write transaction is unrecoverable and is not fabricated.
    /// Follows the `causal_status: legacy_unknown` precedent.
    GroupingUnknown,
}

/// What a replica says about the records it holds — the second axis of
/// partiality (`docs/honest-absence-contract.md` §2). Record-level horizontal
/// subsets are kept reachable by 3854595 and not scheduled by it, so this is
/// `Complete` on every replica that can exist today. It is present rather than
/// deferred so the disclosure does not have to change shape when they arrive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordHolding {
    Complete,
}

/// How a replica describes what it holds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HoldingDisclosure {
    pub contract: &'static str,
    pub acts: ActRange,
    pub window: HoldingWindow,
    /// The act through which the base projection reflects every event. Kept
    /// separate from `acts.from` because they answer different questions: this
    /// one is why record-shaped reads stay complete under a time window, that
    /// one is how far back history goes.
    pub projection_complete_at: i64,
    pub records: RecordHolding,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub below_window: Option<BelowWindow>,
    /// Oldest `content_events.seq` held. The disclosure speaks in acts; the
    /// as-of and `whats_changed` guards speak in content positions, because
    /// that is the coordinate their callers pass. Not serialized: it is an
    /// internal guard input, not part of the published contract.
    #[serde(skip)]
    pub retained_content_floor: i64,
}

impl HoldingDisclosure {
    /// The complete-holding disclosure, for a database that reaches genesis.
    pub fn complete(through_act: i64) -> Self {
        Self {
            contract: HOLDING_CONTRACT,
            acts: ActRange {
                from: None,
                through: through_act,
            },
            window: HoldingWindow::Infinity,
            projection_complete_at: through_act,
            records: RecordHolding::Complete,
            below_window: None,
            retained_content_floor: 1,
        }
    }

    /// Observe what this database actually holds.
    ///
    /// Three cases, in the order they are tested:
    ///
    /// 1. **Pre-cutover rows survive** (`act IS NULL`). The log reaches back
    ///    past the act number itself, so holding reaches genesis, and the
    ///    region below the cutover is `grouping_unknown` rather than absent.
    /// 2. **The oldest act is the first act.** Genesis, window = ∞.
    /// 3. **The oldest act is above the first act.** The log has been
    ///    compacted; everything below it is `not_held`.
    pub async fn observe(conn: &mut sqlx::SqliteConnection) -> Result<Self> {
        // Across all ten canonical logs, not `content_events` alone. The act
        // counter is per workspace, so the oldest act in the content log is
        // routinely above the first act the workspace ever allocated — a
        // schema-seeding write to `meta_events` takes act 1 on a database that
        // is unambiguously complete. Asking one log whether the workspace
        // reaches genesis gets the wrong answer on every fresh database.
        //
        // Read from the *edges* rather than with MIN(act)/MAX(act). `act` is
        // unindexed, so aggregating over it is ten full table scans on a read
        // path that runs per as-of read and per `whats_changed` page. `seq` is
        // each log's INTEGER PRIMARY KEY and `act` is monotonic with it within
        // a log, so the oldest and newest acts are two b-tree edge descents
        // per table and the answer is identical.
        //
        // Table names come from the frozen `CANONICAL_EVENT_TABLES` constant,
        // so this interpolation carries no caller input, and the act-coverage
        // test keeps that list exhaustive.
        let per_table = crate::act::CANONICAL_EVENT_TABLES
            .iter()
            .map(|table| {
                format!(
                    "SELECT (SELECT act FROM {table} ORDER BY seq ASC LIMIT 1) AS lo, \
                            (SELECT act FROM {table} ORDER BY seq DESC LIMIT 1) AS hi, \
                            EXISTS(SELECT 1 FROM {table}) AS present"
                )
            })
            .collect::<Vec<_>>()
            .join(" UNION ALL ");
        let edges: Vec<(Option<i64>, Option<i64>, i64)> =
            sqlx::query_as(&format!("SELECT lo, hi, present FROM ({per_table})"))
                .fetch_all(&mut *conn)
                .await?;

        // A non-empty log whose oldest row carries no act predates acd735f's
        // cutover: unstamped rows sort below every stamped one, so this is the
        // same test as "unstamped rows survive" without scanning for them.
        let pre_cutover = edges
            .iter()
            .any(|(lo, _, present)| *present == 1 && lo.is_none()) as i64;
        let min_act = edges.iter().filter_map(|(lo, _, _)| *lo).min();
        let max_act = edges.iter().filter_map(|(_, hi, _)| *hi).max();
        // The content floor is a separate question in a separate coordinate:
        // the as-of and `whats_changed` guards are handed a content position,
        // not an act.
        let min_seq: Option<i64> = sqlx::query_scalar("SELECT MIN(seq) FROM content_events")
            .fetch_one(&mut *conn)
            .await?;
        let through = max_act.unwrap_or(0);
        // An empty log holds nothing and elides nothing: genesis with no
        // history is complete, not windowed.
        let content_floor = min_seq.unwrap_or(1);

        if pre_cutover > 0 {
            return Ok(Self {
                below_window: Some(BelowWindow::GroupingUnknown),
                retained_content_floor: content_floor,
                ..Self::complete(through)
            });
        }
        match min_act {
            // FIRST_ACT rather than 1: the counter's first allocated value is
            // the authority on what genesis looks like, and reading it from
            // `act` keeps this true if that ever changes.
            None => Ok(Self::complete(through)),
            Some(from) if from <= crate::act::FIRST_ACT => Ok(Self {
                retained_content_floor: content_floor,
                ..Self::complete(through)
            }),
            Some(from) => Ok(Self {
                contract: HOLDING_CONTRACT,
                acts: ActRange {
                    from: Some(from),
                    through,
                },
                window: HoldingWindow::RetainedActs { from_act: from },
                projection_complete_at: through,
                records: RecordHolding::Complete,
                below_window: Some(BelowWindow::NotHeld),
                retained_content_floor: content_floor,
            }),
        }
    }

    /// Whether this replica holds the whole log, and the contract is therefore
    /// vacuous on it.
    pub fn is_complete(&self) -> bool {
        matches!(self.window, HoldingWindow::Infinity)
    }

    /// Guard for reads that pin a content position: as-of selectors and
    /// `whats_changed` baselines.
    ///
    /// A position is answerable when the events after it are all held. The
    /// floor itself is the oldest held event, so the oldest answerable
    /// position is the one immediately before it — which at window = ∞ is
    /// `0`, and every caller-supplied position is `>= 0`. That is why this is
    /// unconditionally true today.
    pub fn holds_content_position(&self, content_seq: i64) -> bool {
        content_seq >= self.retained_content_floor - 1
    }

    /// The refusal a windowed replica owes a caller reading below it. Names
    /// the window so the caller can route to the authority rather than retry
    /// locally — retrying here returns the same answer forever.
    pub fn not_held(&self, surface: &str, what: &str) -> Error {
        let window = match self.acts.from {
            Some(from) => format!("acts {from}..{}", self.acts.through),
            None => format!("acts ..{}", self.acts.through),
        };
        Error::not_held(format!(
            "{surface}: not_held — {what} is below this replica's history window ({window}). \
             The answer exists at the authority; this replica cannot produce it, and \
             retrying here will not change that."
        ))
    }
}

/// How one read surface behaves when what it was asked for is not held, on one
/// axis of partiality (`docs/honest-absence-contract.md` §4).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldingSensitivity {
    /// The answer is a function of the base projection alone. A time window
    /// cannot affect it: the projection is an accumulator and already reflects
    /// every event below W.
    Unaffected,
    /// The answer is a set that may be partial. It is returned with the
    /// missing part disclosed — a per-item `not_held` status, or a
    /// `not_held_count` alongside the items.
    Bounded,
    /// A partial answer is indistinguishable from a whole one, so the surface
    /// refuses rather than answering.
    Refuses,
}

/// A surface's sensitivity on both axes. `NoRead` is for tools that only
/// mutate: they have no answer to be partial about.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldingClassification {
    NoRead,
    Reads {
        /// Axis T — the history window ratified in 3854595.
        time: HoldingSensitivity,
        /// Axis R — record-level horizontal subsets, reachable but unscheduled.
        records: HoldingSensitivity,
    },
}

impl HoldingClassification {
    /// Every read surface is `Bounded` on the record axis unless it refuses:
    /// a horizontal subset can make any answer short. This is the common case
    /// and exists so the classification table reads as a statement about the
    /// time axis, which is the one that ships next.
    pub const fn reads(time: HoldingSensitivity) -> Self {
        Self::Reads {
            time,
            records: HoldingSensitivity::Bounded,
        }
    }

    pub const fn has_read(self) -> bool {
        matches!(self, Self::Reads { .. })
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::db::create_database;
    use crate::mcp::interactions::ToolKind;
    use crate::schema::ROOT_RECORD_ID;
    use crate::store::create_record;

    async fn seeded() -> crate::db::Db {
        let db = create_database(":memory:").await.unwrap();
        for (n, id) in [
            "b1000000-0000-4000-8000-000000000001",
            "b1000000-0000-4000-8000-000000000002",
            "b1000000-0000-4000-8000-000000000003",
        ]
        .iter()
        .enumerate()
        {
            create_record(
                &db,
                json!({
                    "id": id,
                    "type": "Collection",
                    "kind": "folder",
                    "name": format!("folder {n}"),
                    "home_id": ROOT_RECORD_ID,
                }),
            )
            .await
            .unwrap();
        }
        db
    }

    /// Acceptance criterion 1 of the contract's §9: at window = ∞ the whole
    /// thing is inert. This is what makes it safe to land ahead of the
    /// windowing mechanism it protects.
    #[tokio::test]
    async fn a_database_holding_genesis_discloses_complete_holding() {
        let db = seeded().await;
        let holding = HoldingDisclosure::observe(&mut db.write_pool().acquire().await.unwrap())
            .await
            .unwrap();

        assert!(holding.is_complete(), "a full log is not a window");
        assert_eq!(holding.acts.from, None, "from: None is the genesis marker");
        assert!(holding.acts.through > 0, "writes allocate acts");
        assert_eq!(holding.below_window, None, "nothing is below an ∞ window");

        // The guard that every affected read runs. At ∞ it must pass for
        // every position a caller can supply, including 0.
        for position in [0, 1, 2, holding.acts.through, i64::MAX] {
            assert!(
                holding.holds_content_position(position),
                "position {position} must be answerable at window = infinity"
            );
        }
    }

    /// Acceptance criterion 2: with a fabricated window, the guard refuses
    /// exactly the positions below it and no others. The fabrication deletes
    /// the oldest events, which is what compaction will do.
    #[tokio::test]
    async fn a_windowed_log_refuses_positions_below_the_floor() {
        let db = seeded().await;
        // Fabricate a window the way compaction will make one: discard the
        // events below an act boundary across *every* canonical log. Pruning
        // one log is not a window — the workspace still reaches genesis
        // through the other nine, and the disclosure correctly says so.
        let cut_act: i64 = sqlx::query_scalar("SELECT MAX(act) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();
        for table in crate::act::CANONICAL_EVENT_TABLES {
            // The canonical logs carry append-only triggers, so the fixture
            // has to drop them to prune. That is not a test workaround to
            // route around later: it is the first concrete thing compaction
            // will have to face, and it is recorded on the task rather than
            // solved here.
            sqlx::query(&format!("DROP TRIGGER IF EXISTS {table}_no_delete"))
                .execute(db.write_pool())
                .await
                .unwrap();
            sqlx::query(&format!("DELETE FROM {table} WHERE act < ?"))
                .bind(cut_act)
                .execute(db.write_pool())
                .await
                .unwrap();
        }
        let floor: i64 = sqlx::query_scalar("SELECT MIN(seq) FROM content_events")
            .fetch_one(db.write_pool())
            .await
            .unwrap();

        let holding = HoldingDisclosure::observe(&mut db.write_pool().acquire().await.unwrap())
            .await
            .unwrap();
        assert!(!holding.is_complete(), "a compacted log is a window");
        assert_eq!(holding.below_window, Some(BelowWindow::NotHeld));
        assert_eq!(
            holding.window,
            HoldingWindow::RetainedActs { from_act: cut_act },
            "the window states where the retained history begins"
        );
        assert_eq!(holding.acts.from, Some(cut_act));

        assert!(
            !holding.holds_content_position(floor - 2),
            "a position below the floor is not answerable"
        );
        assert!(
            holding.holds_content_position(floor - 1),
            "the position immediately below the oldest held event is the base, \
             and is answerable"
        );
        assert!(holding.holds_content_position(floor));

        // The refusal says not_held, names the window, and tells the caller
        // that retrying locally is pointless. A bare "not found" here is the
        // failure the whole contract exists to prevent.
        let refusal = holding.not_held("as_of", "the state at content_seq 1");
        assert!(
            matches!(refusal, Error::NotHeld(_)),
            "a caller must be able to classify this without parsing the message \
             — the same reason Conflict is its own variant"
        );
        let message = refusal.to_string();
        assert!(message.contains("not_held"), "{message}");
        assert!(message.contains("authority"), "{message}");
    }

    /// Pre-cutover rows predate the act number, so the log reaches genesis and
    /// the region below the cutover is grouping-unknown rather than absent —
    /// acd735f's `legacy_unknown` precedent, not a window.
    #[tokio::test]
    async fn unstamped_legacy_rows_are_grouping_unknown_not_a_window() {
        let db = seeded().await;
        // Same fixture concession as the window test: the canonical logs are
        // append-only by trigger, so backdating a row to the pre-cutover state
        // means dropping the guard first.
        sqlx::query("DROP TRIGGER IF EXISTS content_events_no_update")
            .execute(db.write_pool())
            .await
            .unwrap();
        sqlx::query("UPDATE content_events SET act = NULL WHERE seq = (SELECT MIN(seq) FROM content_events)")
            .execute(db.write_pool())
            .await
            .unwrap();

        let holding = HoldingDisclosure::observe(&mut db.write_pool().acquire().await.unwrap())
            .await
            .unwrap();
        assert!(
            holding.is_complete(),
            "reaching past the act cutover is reaching genesis"
        );
        assert_eq!(holding.below_window, Some(BelowWindow::GroupingUnknown));
        assert_eq!(holding.acts.from, None);
    }

    /// Acceptance criterion 3: every surface that can read has decided what it
    /// does over a partial replica. The exhaustive match in `interactions.rs`
    /// enforces that a new tool chooses; this asserts the choice is coherent
    /// with the tool's own read/write disposition, which is the part the
    /// compiler cannot check.
    #[test]
    fn every_read_surface_classifies_its_holding_behaviour() {
        for kind in ToolKind::ALL {
            let classification = kind.holding_classification();
            if kind.authoritative_disposition().has_read_operation() {
                assert!(
                    classification.has_read(),
                    "{} can read and must say what it does over a partial replica",
                    kind.name()
                );
            }
        }
    }

    #[test]
    fn the_disclosure_serializes_as_the_published_contract() {
        let complete = serde_json::to_value(HoldingDisclosure::complete(41207)).unwrap();
        assert_eq!(
            complete,
            json!({
                "contract": "native.holding-disclosure.v1",
                "acts": { "from": null, "through": 41207 },
                "window": "infinity",
                "projection_complete_at": 41207,
                "records": "complete"
            }),
            "below_window is absent, not null, when nothing is below the window"
        );
    }
}
