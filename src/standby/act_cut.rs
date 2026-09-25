//! Bounded authority-side whole-act range cut for standby delta refresh.
//!
//! Slice 2b of cb551d7, extended by prerequisite 781a566a and Slice 2c. This
//! is the read core only: it cuts the thirteen act-stamped canonical tables
//! over one act interval `(from_exclusive_act, to_inclusive_act]` inside a
//! single SQLite read transaction, then selects the bounded immutable-companion
//! and blob closure from those rows through the fixed edges in
//! [`super::companion_closure`]. It deliberately ships no HTTP/MCP adapter, no
//! snapshot handle, no canonical final delta envelope or digest (later Slice
//! 2d), no receiver/materialiser/projectors, no promotion, no status, and no
//! docs claiming those are done.
//!
//! The read runs in one SQLite deferred transaction: the head probe's first
//! `SELECT` establishes the connection's read snapshot, and every later
//! act-range and companion select stays on it. The cut makes no stronger claim
//! than that snapshot plus the append-only, monotonic character of canonical
//! rows: companions are immutable, act-stamped rows are append-only, and no
//! selected identifier is ever re-resolved outside the same read. The
//! transaction is still rolled back, and a backend that could not offer the
//! same read snapshot would still be safe on append-only canonical state.
//!
//! The cut is over acts, never independent per-domain ranges: every table is
//! selected with the same `act > F1 AND act <= F2` predicate, ordered by its
//! declared primary key, with the exact interchange [`crate::interchange`]
//! `Column`/`Cell` encoding shared via
//! [`crate::interchange::export_act_range_section`]. There is exactly one
//! canonical cell codec.
//!
//! Whole-act proof is structural: across the thirteen sections every integer
//! act in `(F1, F2]` must appear at least once and no act outside the
//! interval may appear. An empty interval (`F1 == F2`) is valid and yields
//! thirteen empty sections. A gapped interval — an act in range with no row
//! anywhere — is refused, as is any tampered section (out-of-range or NULL
//! act, wrong inventory/order, broken primary-key order, non-revision-5
//! shape).
//!
//! Bounds are validated against the authority act head observed in the *same*
//! consistent read transaction via the accepted Slice 2a probe
//! ([`super::authority_probe::read_authority_act_head_on`]): negative bounds,
//! reversed ranges, and `to` beyond that observed head are refused. The probe
//! also keeps the live-authority guards (native revision 5, governed binding
//! seeds, empty webhooks) on the delta path; this slice adds no pins beyond
//! relying on that accepted head. Only live-authority revision-5 rows are
//! cut — legacy grouping-unknown `NULL`-act rows never match the range
//! predicate and any `NULL` act in the emitted sections fails validation.

#![allow(dead_code)] // v1 cut core; the delta adapter wires it later.

use std::collections::BTreeSet;

use sqlx::SqliteConnection;

use crate::error::{Error, Result};

/// Bounded whole-act cut over exactly [`crate::act::ACT_STAMPED_TABLES`], plus
/// the bounded immutable-companion and blob closure selected from those rows.
#[derive(Clone, Debug)]
pub(crate) struct AuthorityActCut {
    from_exclusive_act: i64,
    to_inclusive_act: i64,
    head_act: i64,
    /// The full authority head observed in the same read transaction as the
    /// rows, or `None` for a cut reconstructed from wire bytes, which carries
    /// no local observation. An authority-local cut always has `Some`, and its
    /// `head_act` is derived from that head, so the two cannot disagree.
    observed_head: Option<super::authority_probe::AuthorityActHeadV2>,
    sections: Vec<crate::interchange::Section>,
    companions: Vec<crate::interchange::Section>,
}

impl AuthorityActCut {
    #[allow(clippy::wrong_self_convention)] // names the interval boundary carried by the cut
    pub(crate) fn from_exclusive_act(&self) -> i64 {
        self.from_exclusive_act
    }

    pub(crate) fn to_inclusive_act(&self) -> i64 {
        self.to_inclusive_act
    }

    pub(crate) fn head_act(&self) -> i64 {
        self.head_act
    }

    /// The full authority head observed in the same read transaction, or
    /// `None` when this cut was reconstructed from wire bytes and therefore
    /// makes no local observation. A wire cut must never be presented as a
    /// local observation, and no engine schema is fabricated to fake one.
    pub(crate) fn observed_head(&self) -> Option<&super::authority_probe::AuthorityActHeadV2> {
        self.observed_head.as_ref()
    }

    pub(crate) fn sections(&self) -> &[crate::interchange::Section] {
        &self.sections
    }

    pub(crate) fn section(&self, table: &str) -> Option<&crate::interchange::Section> {
        self.sections.iter().find(|section| section.name == table)
    }

    /// The immutable-companion and blob sections of this cut, in
    /// [`super::companion_closure::COMPANION_TABLES`] order.
    pub(crate) fn companions(&self) -> &[crate::interchange::Section] {
        &self.companions
    }

    pub(crate) fn companion(&self, table: &str) -> Option<&crate::interchange::Section> {
        self.companions.iter().find(|section| section.name == table)
    }

    /// Authority-side constructor: `head_act` and the retained observation are
    /// derived from one `observed_head` value, so same-observation holds by
    /// construction.
    ///
    /// `pub(super)` keeps this inside the standby module tree: no unrelated
    /// crate module can mint a cut that claims a local observation.
    pub(super) fn from_observed_head(
        observed_head: super::authority_probe::AuthorityActHeadV2,
        from_exclusive_act: i64,
        to_inclusive_act: i64,
        sections: Vec<crate::interchange::Section>,
        companions: Vec<crate::interchange::Section>,
    ) -> Self {
        Self {
            from_exclusive_act,
            to_inclusive_act,
            head_act: observed_head.head_act,
            observed_head: Some(observed_head),
            sections,
            companions,
        }
    }

    /// Wire-side reconstruction seam for a cut parsed from an already closed
    /// document. It claims **no** local observation (`observed_head` is
    /// `None`) and performs no validation; the canonical delta validator
    /// parses and structurally validates the wire sections, stores the
    /// validated wire head separately, then calls [`Self::validate`] before the
    /// value is exposed. This is not a bypass; callers must validate first.
    ///
    /// `pub(super)` keeps wire reconstruction inside the standby module tree.
    pub(super) fn from_wire_parts(
        from_exclusive_act: i64,
        to_inclusive_act: i64,
        head_act: i64,
        sections: Vec<crate::interchange::Section>,
        companions: Vec<crate::interchange::Section>,
    ) -> Self {
        Self {
            from_exclusive_act,
            to_inclusive_act,
            head_act,
            observed_head: None,
            sections,
            companions,
        }
    }

    /// Fail-closed structural validation of an authority-produced cut: bounds, exact 13-table
    /// inventory/order tied to [`crate::act::ACT_STAMPED_TABLES`] and the
    /// standby classification, revision-5 section shape with strictly
    /// increasing primary-key order, exact in-range non-NULL acts on every
    /// row, and the whole-act coverage proof.
    ///
    /// This does not replace destination-schema validation for a future
    /// serialized delta. The authority reader derives each section from the
    /// live schema; any receiver must independently pin columns and primary
    /// keys to its destination schema before applying rows.
    pub(crate) fn validate(&self) -> Result<()> {
        // An authority-local cut retains the full head it observed in the same
        // transaction. Re-validating it here keeps origin, policy pin and every
        // other coordinate load-bearing, and `head_act` must be that head's act
        // so the observation cannot drift from the bounds it was read with. Its
        // `to` may legitimately precede the observed head (a supported
        // sub-range). A wire cut has no local observation, so it carries no
        // supported range beyond its head act and must end exactly there; the
        // canonical delta validator already enforces that cross-check, and this
        // keeps any other wire-origin cut honest.
        match &self.observed_head {
            Some(observed_head) => {
                observed_head.validate()?;
                require(
                    observed_head.head_act == self.head_act,
                    "authority act cut head act disagrees with its observed head",
                )?;
            }
            None => {
                require(
                    self.to_inclusive_act == self.head_act,
                    "authority act cut with no observed head must end at its head act",
                )?;
            }
        }
        require(
            self.from_exclusive_act >= 0 && self.to_inclusive_act >= 0,
            "authority act cut bounds must be non-negative",
        )?;
        require(
            self.from_exclusive_act <= self.to_inclusive_act,
            "authority act cut range is reversed",
        )?;
        require(
            self.to_inclusive_act <= self.head_act,
            "authority act cut extends beyond the observed act head",
        )?;
        require(self.head_act >= 0, "authority act cut head is negative")?;

        // Exact inventory and order: no parallel hand-maintained list. The
        // sections must name exactly ACT_STAMPED_TABLES in that order.
        require(
            self.sections.len() == crate::act::ACT_STAMPED_TABLES.len(),
            "authority act cut section inventory is incomplete",
        )?;
        for (section, expected) in self.sections.iter().zip(crate::act::ACT_STAMPED_TABLES) {
            require(
                section.name == expected,
                "authority act cut section inventory or order drifted from ACT_STAMPED_TABLES",
            )?;
            require(
                section.format == crate::interchange::SECTION_FORMAT,
                "authority act cut section format is not the canonical section",
            )?;
            require(
                section.revision == crate::interchange::REVISION,
                "authority act cut requires native canonical-interchange revision 5",
            )?;
            require(
                crate::interchange::SECTION_NAMES.contains(&section.name.as_str()),
                "authority act cut table is missing from canonical interchange",
            )?;
            let kind = crate::schema::standby_classification::TABLE_CLASSIFICATIONS
                .iter()
                .find_map(|(table, kind)| (*table == section.name.as_str()).then_some(*kind));
            require(
                matches!(
                    kind,
                    Some(
                        crate::schema::standby_classification::StandbyTableKind::SequencedCanonicalLog
                        | crate::schema::standby_classification::StandbyTableKind::NonSequencedActStampedCanonicalLog
                    )
                ),
                "authority act cut table is not a classified act-stamped canonical log",
            )?;
            crate::interchange::validate_section_shape(section).map_err(|error| {
                Error::engine(format!(
                    "authority act cut section '{}' is malformed: {error}",
                    section.name
                ))
            })?;
        }

        // Per-row acts plus the whole-act coverage proof.
        let mut observed = BTreeSet::new();
        for section in &self.sections {
            let act_index = section
                .columns
                .iter()
                .position(|column| column.name == "act")
                .ok_or_else(|| {
                    Error::engine(format!(
                        "authority act cut section '{}' has no act column",
                        section.name
                    ))
                })?;
            for row in &section.rows {
                let act = match row.get(act_index) {
                    Some(crate::interchange::Cell::Integer(act)) => *act,
                    _ => {
                        return Err(Error::engine(format!(
                            "authority act cut section '{}' carries a non-integer act",
                            section.name
                        )));
                    }
                };
                require(
                    act > self.from_exclusive_act && act <= self.to_inclusive_act,
                    "authority act cut row act is outside the cut interval",
                )?;
                observed.insert(act);
            }
        }
        // Whole-act coverage proof from the sorted observed set: it scales
        // with the delta rather than the requested range, and it performs no
        // `from + 1` arithmetic that could overflow at `i64::MAX`. An empty
        // interval carries no rows; otherwise the first observed act is the
        // checked successor of the lower bound, the last is the upper bound,
        // and every adjacent pair differs by exactly one.
        if self.from_exclusive_act == self.to_inclusive_act {
            require(
                observed.is_empty(),
                "authority act cut empty interval carries rows",
            )?;
        } else {
            let first_expected = self
                .from_exclusive_act
                .checked_add(1)
                .ok_or_else(|| Error::engine("authority act cut lower bound overflows"))?;
            let first = observed.iter().next().ok_or_else(|| {
                Error::engine("authority act cut is missing a whole act in range")
            })?;
            let last = observed.iter().next_back().ok_or_else(|| {
                Error::engine("authority act cut is missing a whole act in range")
            })?;
            require(
                *first == first_expected,
                "authority act cut is missing a whole act in range",
            )?;
            require(
                *last == self.to_inclusive_act,
                "authority act cut is missing a whole act in range",
            )?;
            let mut previous = *first;
            for act in observed.iter().skip(1) {
                require(
                    act.checked_sub(previous) == Some(1),
                    "authority act cut is missing a whole act in range",
                )?;
                previous = *act;
            }
        }
        self.validate_companions()?;
        Ok(())
    }

    /// Fail-closed structural validation of the companion closure: exact
    /// inventory and order tied to
    /// [`super::companion_closure::COMPANION_TABLES`], each section classified
    /// exactly `ImmutableCanonicalCompanion`, never act-stamped, present in the
    /// canonical interchange, revision-5 shaped with strictly increasing
    /// primary keys (which is also duplicate-free), and — for `blobs` — every
    /// row portable.
    ///
    /// Destination-schema pinning for a serialized delta is deliberately not
    /// claimed here; the authority reader derives each companion section's
    /// columns and primary key from the live schema via
    /// [`crate::interchange::section_shape`], so its own shape is correct by
    /// construction.
    fn validate_companions(&self) -> Result<()> {
        require(
            self.companions.len() == super::companion_closure::COMPANION_TABLES.len(),
            "authority act cut companion closure is incomplete",
        )?;
        for (section, expected) in self
            .companions
            .iter()
            .zip(super::companion_closure::COMPANION_TABLES)
        {
            require(
                section.name == expected,
                "authority act cut companion inventory or order drifted",
            )?;
            require(
                section.format == crate::interchange::SECTION_FORMAT,
                "authority act cut companion section format is not the canonical section",
            )?;
            require(
                section.revision == crate::interchange::REVISION,
                "authority act cut companion requires native canonical-interchange revision 5",
            )?;
            require(
                crate::interchange::SECTION_NAMES.contains(&section.name.as_str()),
                "authority act cut companion is missing from canonical interchange",
            )?;
            let kind = crate::schema::standby_classification::TABLE_CLASSIFICATIONS
                .iter()
                .find_map(|(table, kind)| (*table == section.name.as_str()).then_some(*kind));
            require(
                matches!(
                    kind,
                    Some(
                        crate::schema::standby_classification::StandbyTableKind::ImmutableCanonicalCompanion
                    )
                ),
                "authority act cut companion is not a classified immutable companion",
            )?;
            crate::interchange::validate_section_shape(section).map_err(|error| {
                Error::engine(format!(
                    "authority act cut companion '{}' is malformed: {error}",
                    section.name
                ))
            })?;
            if section.name == "blobs" {
                require_blob_section_portable(section)?;
            }
        }
        Ok(())
    }
}

/// Refuse a blob section carrying a nonportable row, or an inline row with no
/// bytes. The live read path refuses missing and external blobs before it
/// builds the section; this is the same rule re-checked on the typed cut so a
/// hand-built cut cannot claim portability it does not have.
fn require_blob_section_portable(section: &crate::interchange::Section) -> Result<()> {
    let storage_tier = section
        .columns
        .iter()
        .position(|column| column.name == "storage_tier")
        .ok_or_else(|| {
            Error::engine("authority act cut blob section has no storage_tier column")
        })?;
    let bytes = section
        .columns
        .iter()
        .position(|column| column.name == "bytes")
        .ok_or_else(|| Error::engine("authority act cut blob section has no bytes column"))?;
    for row in &section.rows {
        match row.get(storage_tier) {
            Some(crate::interchange::Cell::Text(tier)) if tier == "inline" => {}
            _ => {
                return Err(Error::engine(
                    "authority act cut blob section carries a nonportable blob",
                ))
            }
        }
        require(
            !matches!(row.get(bytes), Some(crate::interchange::Cell::Null)),
            "authority act cut blob section carries an inline blob with no bytes",
        )?;
    }
    Ok(())
}

/// Read a bounded whole-act cut inside one consistent read transaction on the
/// read pool. SQLite's deferred transaction establishes its read snapshot at
/// the first head-probe SELECT; all thirteen later selects remain on that
/// snapshot. The transaction is rolled back: the cut is an observation, not
/// a mutation.
pub(crate) async fn read_authority_act_cut(
    db: &crate::Db,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<AuthorityActCut> {
    let mut tx = db.pool().begin().await?;
    let outcome = read_authority_act_cut_on(&mut tx, from_exclusive_act, to_inclusive_act).await;
    let rollback = tx.rollback().await;
    match (outcome, rollback) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error.into()),
        (Ok(cut), Ok(())) => Ok(cut),
    }
}

/// The one-transaction seam: cut the interval on an already-open connection
/// that is inside a consistent read transaction. The Slice 2a head probe and
/// all thirteen range selects run on this connection, so `to` is checked
/// against the head observed in the same snapshot as the rows.
pub(crate) async fn read_authority_act_cut_on(
    conn: &mut SqliteConnection,
    from_exclusive_act: i64,
    to_inclusive_act: i64,
) -> Result<AuthorityActCut> {
    require(
        from_exclusive_act >= 0 && to_inclusive_act >= 0,
        "authority act cut bounds must be non-negative",
    )?;
    require(
        from_exclusive_act <= to_inclusive_act,
        "authority act cut range is reversed",
    )?;

    // The accepted Slice 2a head: same-transaction observation, with the
    // live-authority guards (native rev5, governed seeds, empty webhooks).
    // No additional pins are introduced here.
    let head = super::authority_probe::read_authority_act_head_on(conn).await?;
    require(
        to_inclusive_act <= head.head_act,
        "authority act cut extends beyond the observed act head",
    )?;

    let mut sections = Vec::with_capacity(crate::act::ACT_STAMPED_TABLES.len());
    for table in crate::act::ACT_STAMPED_TABLES {
        sections.push(
            crate::interchange::export_act_range_section(
                conn,
                table,
                from_exclusive_act,
                to_inclusive_act,
            )
            .await?,
        );
    }

    // The bounded immutable-companion and blob closure, selected from the
    // act-stamped rows above through the fixed edges in
    // `companion_closure`, on the same connection and therefore the same read
    // snapshot.
    let companions = super::companion_closure::read_companion_sections_on(
        conn,
        from_exclusive_act,
        to_inclusive_act,
    )
    .await?;

    let cut = AuthorityActCut::from_observed_head(
        head,
        from_exclusive_act,
        to_inclusive_act,
        sections,
        companions,
    );
    cut.validate()?;
    Ok(cut)
}

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(Error::engine(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::interchange::{Cell, Column, Section};

    fn empty_section(table: &str) -> Section {
        Section {
            format: crate::interchange::SECTION_FORMAT.into(),
            revision: crate::interchange::REVISION,
            name: table.into(),
            columns: vec![
                Column {
                    name: "id".into(),
                    declared_type: "TEXT".into(),
                },
                Column {
                    name: "act".into(),
                    declared_type: "INTEGER".into(),
                },
            ],
            primary_key: vec!["id".into()],
            rows: Vec::new(),
        }
    }

    fn section_with_acts(table: &str, acts: &[i64]) -> Section {
        let mut section = empty_section(table);
        for (index, act) in acts.iter().enumerate() {
            section.rows.push(vec![
                Cell::Text(format!("row-{index:04}")),
                Cell::Integer(*act),
            ]);
        }
        section
    }

    /// An empty companion section with a shape that satisfies
    /// `validate_section_shape`; the real read path derives the live shape.
    fn empty_companion_section(table: &str) -> Section {
        let columns = if table == "blobs" {
            vec![
                Column {
                    name: "id".into(),
                    declared_type: "TEXT".into(),
                },
                Column {
                    name: "bytes".into(),
                    declared_type: "BLOB".into(),
                },
                Column {
                    name: "storage_tier".into(),
                    declared_type: "TEXT".into(),
                },
            ]
        } else {
            vec![Column {
                name: "id".into(),
                declared_type: "TEXT".into(),
            }]
        };
        Section {
            format: crate::interchange::SECTION_FORMAT.into(),
            revision: crate::interchange::REVISION,
            name: table.into(),
            columns,
            primary_key: vec!["id".into()],
            rows: Vec::new(),
        }
    }

    fn empty_companions() -> Vec<Section> {
        super::super::companion_closure::COMPANION_TABLES
            .iter()
            .map(|table| empty_companion_section(table))
            .collect()
    }

    fn cut_with_first_section_rows(
        from_exclusive_act: i64,
        to_inclusive_act: i64,
        head_act: i64,
        acts: &[i64],
    ) -> AuthorityActCut {
        let mut sections = Vec::with_capacity(crate::act::ACT_STAMPED_TABLES.len());
        for (index, table) in crate::act::ACT_STAMPED_TABLES.iter().enumerate() {
            if index == 0 {
                sections.push(section_with_acts(table, acts));
            } else {
                sections.push(empty_section(table));
            }
        }
        AuthorityActCut::from_wire_parts(
            from_exclusive_act,
            to_inclusive_act,
            head_act,
            sections,
            empty_companions(),
        )
    }

    fn empty_cut(from_exclusive_act: i64, to_inclusive_act: i64, head_act: i64) -> AuthorityActCut {
        cut_with_first_section_rows(from_exclusive_act, to_inclusive_act, head_act, &[])
    }

    /// The old `(from + 1)..=to` coverage loop evaluated `i64::MAX + 1` even
    /// for the valid empty interval at the top of the range and panicked in
    /// debug builds. The sorted-set proof must accept it without arithmetic
    /// on the bound.
    #[test]
    fn empty_interval_at_i64_max_validates_without_overflow() {
        empty_cut(i64::MAX, i64::MAX, i64::MAX).validate().unwrap();
    }

    /// Extreme bounds refuse fail-closed instead of panicking: a non-empty
    /// top-of-range interval with no rows is a missing act, and `to` beyond
    /// the observed head is refused before any range arithmetic.
    #[test]
    fn extreme_bounds_refuse_without_panic() {
        assert!(empty_cut(i64::MAX - 1, i64::MAX, i64::MAX)
            .validate()
            .is_err());
        assert!(empty_cut(i64::MAX, i64::MAX, i64::MAX - 1)
            .validate()
            .is_err());
    }

    /// A non-empty interval whose observed acts run contiguously from the
    /// checked successor of the lower bound to the upper bound validates,
    /// even when the rows live in a single section of the thirteen.
    #[test]
    fn contiguous_acts_validate_from_the_observed_set() {
        cut_with_first_section_rows(5, 8, 8, &[6, 7, 8])
            .validate()
            .unwrap();
    }

    /// A gap inside the interval is refused: the adjacent observed acts
    /// differ by more than one.
    #[test]
    fn gapped_acts_refuse() {
        assert!(cut_with_first_section_rows(5, 8, 8, &[6, 8])
            .validate()
            .is_err());
    }

    /// A non-empty interval with no rows anywhere is refused rather than
    /// vacuously accepted.
    #[test]
    fn non_empty_interval_with_no_rows_refuses() {
        assert!(empty_cut(5, 8, 8).validate().is_err());
    }

    /// An empty interval carrying rows is refused: `from == to` means no act
    /// can be in range.
    #[test]
    fn empty_interval_with_rows_refuses() {
        assert!(cut_with_first_section_rows(7, 7, 7, &[7])
            .validate()
            .is_err());
    }

    /// A wire-origin cut claims no observed head and therefore carries no
    /// supported range beyond its head act: `to` must equal `head_act`. An
    /// authority-local observed cut keeps its supported sub-range semantics,
    /// which the production read path exercises and the delta tests pin.
    #[test]
    fn wire_cut_without_observed_head_must_end_at_its_head_act() {
        let ending_at_head = cut_with_first_section_rows(5, 8, 8, &[6, 7, 8]);
        assert!(ending_at_head.observed_head().is_none());
        ending_at_head.validate().unwrap();

        let short_wire = cut_with_first_section_rows(5, 7, 8, &[6, 7]);
        assert!(short_wire.observed_head().is_none());
        assert!(short_wire.validate().is_err());
    }

    // Production-read fixtures below. Every database row here is written
    // through the real append seams sharing one `ActAllocation` per
    // transaction, exactly as the authority does; no test inserts act-stamped
    // rows by hand.

    async fn fresh_authority() -> crate::Db {
        crate::db::create_database(":memory:").await.unwrap()
    }

    async fn live_head_act(db: &crate::Db) -> i64 {
        super::super::authority_probe::read_authority_act_head(db)
            .await
            .unwrap()
            .head_act
    }

    async fn append_record(db: &crate::Db, record_id: &str, name: &str) {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                }),
                actor: None,
            },
        )
        .await
        .unwrap();
    }

    fn section_acts(section: &Section) -> Vec<i64> {
        let act_index = section
            .columns
            .iter()
            .position(|column| column.name == "act")
            .expect("cut sections carry an act column");
        section
            .rows
            .iter()
            .map(|row| match &row[act_index] {
                Cell::Integer(act) => *act,
                _ => panic!("cut rows carry non-NULL integer acts"),
            })
            .collect()
    }

    fn cell_text_key(cell: &Cell) -> String {
        match cell {
            Cell::Integer(value) => value.to_string(),
            Cell::Text(value) => value.clone(),
            _ => panic!("primary-key and act cells are integer or text"),
        }
    }

    /// Pin one cut section against the live database: the declared primary
    /// key matches `PRAGMA table_info`, and the exact `(first_pk, act)` pairs
    /// in PK order match a direct range read.
    async fn assert_section_matches_live_rows(
        db: &crate::Db,
        cut: &AuthorityActCut,
        table: &str,
        from_exclusive_act: i64,
        to_inclusive_act: i64,
    ) {
        let section = cut
            .section(table)
            .unwrap_or_else(|| panic!("cut carries {table}"));
        let live_pk: Vec<String> = sqlx::query_scalar(&format!(
            "SELECT name FROM pragma_table_info('{table}') WHERE pk > 0 ORDER BY pk"
        ))
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert_eq!(
            section.primary_key, live_pk,
            "declared primary key drifted for {table}"
        );
        let first_pk = &section.primary_key[0];
        let order = section
            .primary_key
            .iter()
            .map(|column| format!("\"{}\"", column.replace('"', "\"\"")))
            .collect::<Vec<_>>()
            .join(", ");
        let sql = format!(
            "SELECT CAST(\"{first_pk}\" AS TEXT), CAST(act AS TEXT) FROM \"{table}\" WHERE act > ? AND act <= ? ORDER BY {order}"
        );
        let live_pairs: Vec<(String, String)> = sqlx::query_as(&sql)
            .bind(from_exclusive_act)
            .bind(to_inclusive_act)
            .fetch_all(db.pool())
            .await
            .unwrap();
        let pk_index = section
            .columns
            .iter()
            .position(|column| column.name == *first_pk)
            .unwrap();
        let act_index = section
            .columns
            .iter()
            .position(|column| column.name == "act")
            .unwrap();
        let cut_pairs: Vec<(String, String)> = section
            .rows
            .iter()
            .map(|row| {
                (
                    cell_text_key(&row[pk_index]),
                    cell_text_key(&row[act_index]),
                )
            })
            .collect();
        assert_eq!(
            cut_pairs, live_pairs,
            "cut rows diverge from the live range read for {table}"
        );
    }

    /// An empty interval on a live authority returns all thirteen real-schema
    /// sections with zero rows.
    #[tokio::test]
    async fn empty_range_returns_thirteen_empty_real_schema_sections() {
        let db = fresh_authority().await;
        let head = live_head_act(&db).await;
        let cut = read_authority_act_cut(&db, head, head).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(cut.from_exclusive_act(), head);
        assert_eq!(cut.to_inclusive_act(), head);
        assert_eq!(cut.head_act(), head);
        assert_eq!(
            cut.sections()
                .iter()
                .map(|section| section.name.as_str())
                .collect::<Vec<_>>(),
            crate::act::ACT_STAMPED_TABLES,
            "cut inventory and order follow ACT_STAMPED_TABLES"
        );
        for section in cut.sections() {
            assert_eq!(section.format, crate::interchange::SECTION_FORMAT);
            assert_eq!(section.revision, crate::interchange::REVISION);
            assert!(
                section.columns.iter().any(|column| column.name == "act"),
                "real-schema section carries its act column"
            );
            assert!(
                section.rows.is_empty(),
                "empty interval carries no rows in {}",
                section.name
            );
            assert_section_matches_live_rows(&db, &cut, &section.name.clone(), head, head).await;
        }
        db.close().await;
    }

    /// Two consecutive production appends take two consecutive acts, and the
    /// cut selects each boundary exactly.
    #[tokio::test]
    async fn two_consecutive_acts_select_exact_boundaries() {
        let db = fresh_authority().await;
        let base = live_head_act(&db).await;
        append_record(&db, "1a7e4000-0000-4000-8000-0000000000a1", "first").await;
        append_record(&db, "1a7e4000-0000-4000-8000-0000000000a2", "second").await;
        assert_eq!(live_head_act(&db).await, base + 2);

        let both = read_authority_act_cut(&db, base, base + 2).await.unwrap();
        assert_eq!(
            section_acts(both.section("content_events").unwrap()),
            vec![base + 1, base + 2]
        );

        let first = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        assert_eq!(
            section_acts(first.section("content_events").unwrap()),
            vec![base + 1]
        );

        let second = read_authority_act_cut(&db, base + 1, base + 2)
            .await
            .unwrap();
        assert_eq!(
            section_acts(second.section("content_events").unwrap()),
            vec![base + 2]
        );
        db.close().await;
    }

    /// One transaction stamping content and derivation rows with a single act
    /// is never split: every cut either carries that act's rows in both
    /// tables or contains neither.
    #[tokio::test]
    async fn one_multi_domain_transaction_is_never_split() {
        let db = fresh_authority().await;
        let base = live_head_act(&db).await;

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::store::append_in(
            &db,
            &mut tx,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-0000000000b1".into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": "multi-domain act",
                }),
                actor: None,
            },
            &mut alloc,
        )
        .await
        .unwrap();
        crate::derivation::append_derivation_event_in(
            &mut tx,
            crate::derivation::NewDerivationEvent::authored(
                "act-cut-multi-domain-series",
                "act-cut-fixture",
                None,
                "prove whole-act carriage",
                crate::derivation::DerivationEventPayload::SeriesCreated(
                    crate::derivation::DerivationSeriesCreated {
                        id: "act-cut-multi-domain-series".into(),
                        series_key: "act-cut:multi-domain".into(),
                        definition: serde_json::json!({"kind": "test"}),
                    },
                ),
            )
            .unwrap(),
            &mut alloc,
        )
        .await
        .unwrap();
        db.commit_content(tx).await.unwrap();
        append_record(&db, "1a7e4000-0000-4000-8000-0000000000b2", "later").await;
        assert_eq!(live_head_act(&db).await, base + 2);

        let shared = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        assert_eq!(
            section_acts(shared.section("content_events").unwrap()),
            vec![base + 1],
            "the shared act's content row is cut"
        );
        assert_eq!(
            section_acts(shared.section("derivation_events").unwrap()),
            vec![base + 1],
            "the shared act's derivation row travels with it"
        );

        let later = read_authority_act_cut(&db, base + 1, base + 2)
            .await
            .unwrap();
        assert_eq!(
            section_acts(later.section("content_events").unwrap()),
            vec![base + 2]
        );
        assert!(
            later.section("derivation_events").unwrap().rows.is_empty(),
            "the later interval carries no derivation row"
        );
        db.close().await;
    }

    /// A provenance validity change committed on its own allocates an act
    /// carried only by the non-sequenced validity log, and the cut includes
    /// it.
    #[tokio::test]
    async fn provenance_validity_only_act_is_included() {
        let db = fresh_authority().await;
        let caller = crate::mcp::Caller::local();
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "create_record",
            &serde_json::json!({"name": "validity fixture"}),
            None,
        );
        dispatch
            .scope(append_record(
                &db,
                "1a7e4000-0000-4000-8000-0000000000c1",
                "validity fixture",
            ))
            .await;
        let attestation_id = dispatch.receipt_ids().pop().unwrap();
        let base = live_head_act(&db).await;

        let mut validity_tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::provenance::append_validity_event_in(
            &mut validity_tx,
            &mut alloc,
            &attestation_id,
            crate::provenance::ValidityChange::Invalidated,
            "act-cut fixture",
            "act-cut-fixture",
        )
        .await
        .unwrap();
        validity_tx.commit().await.unwrap();
        assert_eq!(live_head_act(&db).await, base + 1);

        let cut = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        let validity_acts = section_acts(
            cut.section("provenance_attestation_validity_events")
                .unwrap(),
        );
        assert_eq!(
            validity_acts,
            vec![base + 1],
            "the validity-only act is cut"
        );
        for section in cut.sections() {
            if section.name == "provenance_attestation_validity_events" {
                continue;
            }
            assert!(
                section.rows.is_empty(),
                "validity-only act leaves {} empty",
                section.name
            );
        }

        let whole = read_authority_act_cut(&db, base - 1, base + 1)
            .await
            .unwrap();
        assert!(!section_acts(whole.section("content_events").unwrap()).is_empty());
        assert!(!section_acts(
            whole
                .section("provenance_attestation_validity_events")
                .unwrap()
        )
        .is_empty());
        db.close().await;
    }

    /// The live read path refuses `to` beyond the same-transaction head as
    /// well as negative and reversed bounds.
    #[tokio::test]
    async fn out_of_range_bounds_refuse() {
        let db = fresh_authority().await;
        let head = live_head_act(&db).await;
        assert!(
            read_authority_act_cut(&db, 0, head + 1).await.is_err(),
            "`to` beyond the observed head refuses"
        );
        assert!(
            read_authority_act_cut(&db, -1, head).await.is_err(),
            "negative `from` refuses"
        );
        assert!(
            read_authority_act_cut(&db, 0, -1).await.is_err(),
            "negative `to` refuses"
        );
        assert!(
            read_authority_act_cut(&db, 1, 0).await.is_err(),
            "reversed range refuses"
        );
        let mut conn = db.pool().acquire().await.unwrap();
        assert!(
            crate::interchange::export_act_range_section(&mut conn, "content_events", -1, head,)
                .await
                .is_err(),
            "the shared section reader also refuses negative bounds"
        );
        assert!(
            crate::interchange::export_act_range_section(&mut conn, "content_events", 1, 0,)
                .await
                .is_err(),
            "the shared section reader also refuses reversed bounds"
        );
        drop(conn);
        db.close().await;
    }

    /// Over a populated authority, the cut inventory and order are exactly
    /// `ACT_STAMPED_TABLES`, every section's declared primary key matches the
    /// live schema, and every section's rows in PK order match a direct range
    /// read.
    #[tokio::test]
    async fn section_inventory_order_and_pk_rows_match_live_schema() {
        let db = fresh_authority().await;
        let base = live_head_act(&db).await;
        append_record(&db, "1a7e4000-0000-4000-8000-0000000000d1", "first").await;
        append_record(&db, "1a7e4000-0000-4000-8000-0000000000d2", "second").await;
        let head = live_head_act(&db).await;
        assert_eq!(head, base + 2);

        let cut = read_authority_act_cut(&db, base, head).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            cut.sections()
                .iter()
                .map(|section| section.name.as_str())
                .collect::<Vec<_>>(),
            crate::act::ACT_STAMPED_TABLES,
            "cut inventory and order follow ACT_STAMPED_TABLES"
        );
        for table in crate::act::ACT_STAMPED_TABLES {
            assert_section_matches_live_rows(&db, &cut, table, base, head).await;
        }
        db.close().await;
    }

    /// Prerequisite 781a566a whole-act cases: observation-only, intent-only,
    /// captured-observation+content, and batch-intent+awareness each occupy
    /// exactly one act, and the cut carries that act whole.

    #[tokio::test]
    async fn observation_only_act_is_carried_whole() {
        let db = fresh_authority().await;
        let actor = crate::identity::resolve_stdio_account_identity(&db, None)
            .await
            .unwrap();
        let claim = crate::identity::BindingClaim {
            system: "native-principal".into(),
            identifier: "native/cut-observation-only".into(),
        };
        // Setup: create the shadow once (stub content + first observation
        // share their act). The act under test is the second observation, a
        // pure binding hit with no content appends.
        crate::identity::observe_external(
            &db,
            &crate::identity::MutationContext {
                actor: &actor,
                reason: "cut observation setup",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: false,
                source_read_authorized: false,
            },
            std::slice::from_ref(&claim),
            &crate::identity::StubHints {
                name: Some("Cut observation".into()),
                ..Default::default()
            },
            &claim,
            crate::identity::ObservationQuality::Reported,
            crate::identity::MaterializationPolicy::IdentityOnly,
            None,
            &crate::identity::ObservationProvenance::default(),
            Some("Cut observation"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let base = live_head_act(&db).await;
        crate::identity::observe_external(
            &db,
            &crate::identity::MutationContext {
                actor: &actor,
                reason: "cut observation-only",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: false,
                source_read_authorized: false,
            },
            std::slice::from_ref(&claim),
            &crate::identity::StubHints {
                name: Some("Cut observation".into()),
                ..Default::default()
            },
            &claim,
            crate::identity::ObservationQuality::Reported,
            crate::identity::MaterializationPolicy::IdentityOnly,
            None,
            &crate::identity::ObservationProvenance::default(),
            Some("Cut observation"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        assert_eq!(live_head_act(&db).await, base + 1);

        let cut = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            section_acts(cut.section("external_observations").unwrap()),
            vec![base + 1]
        );
        for section in cut.sections() {
            if section.name == "external_observations" {
                continue;
            }
            assert!(
                section.rows.is_empty(),
                "observation-only act leaves {} empty",
                section.name
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn intent_only_act_is_carried_whole() {
        let db = fresh_authority().await;
        let base = live_head_act(&db).await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::awareness::register_human_batch_command(
            &mut tx,
            "acct:cut-intent-only",
            crate::awareness::HumanStage::Acknowledged,
            &[],
            &std::collections::BTreeMap::new(),
            "cut-intent-only-key",
            None,
            &crate::awareness::VerifiedHumanInteraction {
                nonce: "cut-intent".into(),
                executor_ref: "ui".into(),
            },
            "cut",
            &mut alloc,
        )
        .await
        .unwrap();
        db.commit_awareness(tx).await.unwrap();
        assert_eq!(live_head_act(&db).await, base + 1);

        let cut = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            section_acts(cut.section("awareness_command_intents").unwrap()),
            vec![base + 1]
        );
        for section in cut.sections() {
            if section.name == "awareness_command_intents" {
                continue;
            }
            assert!(
                section.rows.is_empty(),
                "intent-only act leaves {} empty",
                section.name
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn captured_observation_shares_content_act_whole() {
        let db = fresh_authority().await;
        let actor = crate::identity::resolve_stdio_account_identity(&db, None)
            .await
            .unwrap();
        let claim = crate::identity::BindingClaim {
            system: "native-principal".into(),
            identifier: "native/cut-captured".into(),
        };
        // Setup: create the shadow once so the captured transaction below is
        // a pure hit plus exactly the three attachment content appends.
        crate::identity::observe_external(
            &db,
            &crate::identity::MutationContext {
                actor: &actor,
                reason: "cut captured setup",
                run_key: None,
                parent_key: None,
                intent: None,
                is_member: true,
                internal: false,
                source_read_authorized: false,
            },
            std::slice::from_ref(&claim),
            &crate::identity::StubHints::default(),
            &claim,
            crate::identity::ObservationQuality::Reported,
            crate::identity::MaterializationPolicy::IdentityOnly,
            None,
            &crate::identity::ObservationProvenance::default(),
            Some("Cut captured"),
            None,
            None,
            None,
        )
        .await
        .unwrap();
        let base = live_head_act(&db).await;
        let mut trusted = crate::identity::MutationContext {
            actor: &actor,
            reason: "cut captured",
            run_key: None,
            parent_key: None,
            intent: None,
            is_member: true,
            internal: false,
            source_read_authorized: true,
        };
        // Internal + source-read authority is required for snapshot capture;
        // the fixture actor is a member, so only the flags need lifting.
        trusted.internal = true;
        crate::identity::observe_external(
            &db,
            &trusted,
            std::slice::from_ref(&claim),
            &crate::identity::StubHints::default(),
            &claim,
            crate::identity::ObservationQuality::Fetched,
            crate::identity::MaterializationPolicy::Snapshot,
            None,
            &crate::identity::ObservationProvenance {
                source_revision: Some("cut-rev-1".into()),
                source_digest: Some("source:cut1".into()),
                freshness: crate::identity::ObservationFreshness::Fresh,
                retention_state: crate::identity::RetentionState::Captured,
                source_availability: crate::identity::SourceAvailability::Available,
                refresh_outcome: crate::identity::RefreshOutcome::Succeeded,
                retained_from_observation_id: None,
            },
            None,
            Some(b"cut body"),
            Some("text/plain"),
            Some("cut.txt"),
        )
        .await
        .unwrap();
        assert_eq!(live_head_act(&db).await, base + 1);

        let cut = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        cut.validate().unwrap();
        let observation_acts = section_acts(cut.section("external_observations").unwrap());
        assert_eq!(observation_acts, vec![base + 1]);
        let content_acts = section_acts(cut.section("content_events").unwrap());
        assert_eq!(content_acts.len(), 3);
        assert!(content_acts.iter().all(|act| *act == base + 1));
        for section in cut.sections() {
            if section.name == "external_observations" || section.name == "content_events" {
                continue;
            }
            assert!(
                section.rows.is_empty(),
                "captured+content act leaves {} empty",
                section.name
            );
        }
        db.close().await;
    }

    #[tokio::test]
    async fn batch_intent_shares_awareness_act_whole() {
        let db = fresh_authority().await;
        let base = live_head_act(&db).await;
        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let attestation = crate::awareness::VerifiedHumanInteraction {
            nonce: "cut-batch".into(),
            executor_ref: "ui".into(),
        };
        let message_ids = vec!["cut-msg-1".to_string(), "cut-msg-2".to_string()];
        let expected = std::collections::BTreeMap::from([
            ("cut-msg-1".to_string(), 0),
            ("cut-msg-2".to_string(), 0),
        ]);
        let first = crate::awareness::register_human_batch_command(
            &mut tx,
            "acct:cut-batch",
            crate::awareness::HumanStage::Acknowledged,
            &message_ids,
            &expected,
            "cut-batch-key",
            None,
            &attestation,
            "cut",
            &mut alloc,
        )
        .await
        .unwrap();
        assert!(first);
        for message_id in &message_ids {
            crate::awareness::advance_human(
                &mut tx,
                "acct:cut-batch",
                message_id,
                crate::awareness::HumanStage::Acknowledged,
                0,
                &format!("cut-batch-key:{message_id}"),
                &attestation,
                "cut",
                &mut alloc,
            )
            .await
            .unwrap();
        }
        db.commit_awareness(tx).await.unwrap();
        assert_eq!(live_head_act(&db).await, base + 1);

        let cut = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            section_acts(cut.section("awareness_command_intents").unwrap()),
            vec![base + 1]
        );
        let awareness_acts = section_acts(cut.section("awareness_events").unwrap());
        assert_eq!(awareness_acts.len(), 2);
        assert!(awareness_acts.iter().all(|act| *act == base + 1));
        for section in cut.sections() {
            if section.name == "awareness_command_intents" || section.name == "awareness_events" {
                continue;
            }
            assert!(
                section.rows.is_empty(),
                "batch+awareness act leaves {} empty",
                section.name
            );
        }
        db.close().await;
    }

    // ---- Slice 2c: bounded immutable-companion and blob closure ----

    async fn append_record_returning(
        db: &crate::Db,
        record_id: &str,
        name: &str,
    ) -> crate::events::EventRow {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "record.created".into(),
                payload: serde_json::json!({
                    "type": "Document",
                    "kind": "note",
                    "name": name,
                }),
                actor: None,
            },
        )
        .await
        .unwrap()
    }

    async fn append_facet_set(
        db: &crate::Db,
        record_id: &str,
        key: &str,
        value: &str,
    ) -> crate::events::EventRow {
        crate::store::append(
            db,
            crate::store::AppendSpec {
                record_id: record_id.into(),
                event_type: "facet.set".into(),
                payload: serde_json::json!({ "key": key, "value": value }),
                actor: None,
            },
        )
        .await
        .unwrap()
    }

    fn companion_text(section: &Section, row: &[Cell], column: &str) -> Option<String> {
        let index = section
            .columns
            .iter()
            .position(|candidate| candidate.name == column)
            .unwrap_or_else(|| panic!("companion {} has no {column}", section.name));
        match &row[index] {
            Cell::Text(value) => Some(value.clone()),
            Cell::Integer(value) => Some(value.to_string()),
            Cell::Null => None,
            other => panic!("unexpected companion cell {other:?}"),
        }
    }

    fn companion_column(section: &Section, column: &str) -> BTreeSet<String> {
        let index = section
            .columns
            .iter()
            .position(|candidate| candidate.name == column)
            .unwrap_or_else(|| panic!("companion {} has no {column}", section.name));
        section
            .rows
            .iter()
            .map(|row| match &row[index] {
                Cell::Text(value) => value.clone(),
                Cell::Integer(value) => value.to_string(),
                other => panic!("unexpected companion key cell {other:?}"),
            })
            .collect()
    }

    fn companion_row_count(cut: &AuthorityActCut, table: &str) -> usize {
        cut.companion(table)
            .unwrap_or_else(|| panic!("cut carries companion {table}"))
            .rows
            .len()
    }

    /// An empty interval still carries all thirteen companion sections, each
    /// with the live schema's exact columns and primary key and no rows.
    #[tokio::test]
    async fn empty_range_carries_thirteen_empty_companion_sections() {
        let db = fresh_authority().await;
        let head = live_head_act(&db).await;
        let cut = read_authority_act_cut(&db, head, head).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            cut.companions()
                .iter()
                .map(|section| section.name.as_str())
                .collect::<Vec<_>>(),
            super::super::companion_closure::COMPANION_TABLES,
        );
        for section in cut.companions() {
            assert_eq!(section.format, crate::interchange::SECTION_FORMAT);
            assert_eq!(section.revision, crate::interchange::REVISION);
            assert!(
                section.rows.is_empty(),
                "empty interval carries companion rows in {}",
                section.name
            );
            let live_pk: Vec<String> = sqlx::query_scalar(&format!(
                "SELECT name FROM pragma_table_info('{}') WHERE pk > 0 ORDER BY pk",
                section.name
            ))
            .fetch_all(db.pool())
            .await
            .unwrap();
            assert_eq!(
                section.primary_key, live_pk,
                "companion primary key drifted for {}",
                section.name
            );
            let live_columns: Vec<(String, String)> = sqlx::query_as(&format!(
                "SELECT name, type FROM pragma_table_info('{}') ORDER BY cid",
                section.name
            ))
            .fetch_all(db.pool())
            .await
            .unwrap();
            let section_columns: Vec<(String, String)> = section
                .columns
                .iter()
                .map(|column| (column.name.clone(), column.declared_type.clone()))
                .collect();
            assert_eq!(
                section_columns, live_columns,
                "companion columns drifted for {}",
                section.name
            );
        }
        db.close().await;
    }

    /// Production appends populate the causal frontier. Cutting the middle
    /// act carries only that act's frontier rows, whose parents are the
    /// out-of-window head; the parent is carried as a column and never walked,
    /// and local events honestly carry no `content_event_sources` row.
    #[tokio::test]
    async fn causal_frontier_is_carried_one_hop_only() {
        let db = fresh_authority().await;
        let first = append_record_returning(&db, "1a7e4000-0000-4000-8000-0000000000e1", "A").await;
        let second =
            append_record_returning(&db, "1a7e4000-0000-4000-8000-0000000000e2", "B").await;
        let third = append_record_returning(&db, "1a7e4000-0000-4000-8000-0000000000e3", "C").await;
        assert_eq!(second.act, Some(first.act.unwrap() + 1));
        assert_eq!(third.act, Some(second.act.unwrap() + 1));

        let cut = read_authority_act_cut(&db, first.act.unwrap(), second.act.unwrap())
            .await
            .unwrap();
        cut.validate().unwrap();
        let frontier = cut
            .companion("content_event_causal_frontier")
            .expect("cut carries the causal frontier");
        assert!(!frontier.rows.is_empty());
        for row in &frontier.rows {
            assert_eq!(
                companion_text(frontier, row, "event_id").as_deref(),
                Some(second.id.as_str()),
                "only the in-window event's frontier rows are cut"
            );
        }
        let parents = companion_column(frontier, "parent_event_id");
        assert_eq!(
            parents,
            BTreeSet::from([first.id.clone()]),
            "the one-hop parent is the out-of-window head"
        );
        assert!(
            cut.companion("content_event_sources")
                .unwrap()
                .rows
                .is_empty(),
            "absence of a source row means a local event"
        );

        // The later act carries only C's frontier, proving no walk into A's
        // own parent set.
        let later = read_authority_act_cut(&db, second.act.unwrap(), third.act.unwrap())
            .await
            .unwrap();
        let later_frontier = later.companion("content_event_causal_frontier").unwrap();
        assert_eq!(
            companion_column(later_frontier, "event_id"),
            BTreeSet::from([third.id.clone()])
        );
        assert_eq!(
            companion_column(later_frontier, "parent_event_id"),
            BTreeSet::from([second.id.clone()])
        );
        db.close().await;
    }

    /// Production `facet.set` and `annotation.target.set` payloads are the only
    /// blob references. Blobs referenced by in-window events are pulled by
    /// primary key; unrelated blobs and blobs referenced only by out-of-window
    /// events are not.
    #[tokio::test]
    async fn blob_closure_selects_only_referenced_in_window_blobs() {
        let db = fresh_authority().await;
        let facet_blob =
            crate::blob::insert_blob(&db, b"facet bytes", Some("text/plain"), Some("f"))
                .await
                .unwrap();
        let annotation_blob = crate::blob::insert_blob(&db, b"annotation bytes", None, None)
            .await
            .unwrap();
        let unrelated_blob = crate::blob::insert_blob(&db, b"unrelated", None, None)
            .await
            .unwrap();
        let later_blob = crate::blob::insert_blob(&db, b"later", None, None)
            .await
            .unwrap();

        let target =
            append_record_returning(&db, "1a7e4000-0000-4000-8000-0000000000e4", "blob target")
                .await;
        let facet_event = append_facet_set(
            &db,
            "1a7e4000-0000-4000-8000-0000000000e4",
            "blob_ref",
            &facet_blob.id,
        )
        .await;
        crate::store::create_record(
            &db,
            serde_json::json!({
                "id": "1a7e4000-0000-4000-8000-0000000000e5",
                "type": "Annotation",
                "kind": "citation",
                "name": "",
            }),
        )
        .await
        .unwrap();
        let annotation_event = crate::store::append(
            &db,
            crate::store::AppendSpec {
                record_id: "1a7e4000-0000-4000-8000-0000000000e5".into(),
                event_type: "annotation.target.set".into(),
                payload: serde_json::json!({
                    "target_record_id": target.record_id,
                    "source_slot": "blob",
                    "blob_id": annotation_blob.id,
                    "source_sha256": "0".repeat(64),
                    "selectors": [],
                }),
                actor: None,
            },
        )
        .await
        .unwrap();

        let cut = read_authority_act_cut(
            &db,
            facet_event.act.unwrap() - 1,
            annotation_event.act.unwrap(),
        )
        .await
        .unwrap();
        cut.validate().unwrap();
        let blobs = cut.companion("blobs").unwrap();
        assert_eq!(
            companion_column(blobs, "id"),
            BTreeSet::from([facet_blob.id.clone(), annotation_blob.id.clone()]),
            "both portable reference shapes are pulled"
        );
        assert!(!companion_column(blobs, "id").contains(&unrelated_blob.id));

        // A later facet.set referencing a fourth blob does not leak backwards.
        let later_event = append_facet_set(
            &db,
            "1a7e4000-0000-4000-8000-0000000000e4",
            "blob_ref",
            &later_blob.id,
        )
        .await;
        let earlier = read_authority_act_cut(
            &db,
            facet_event.act.unwrap() - 1,
            annotation_event.act.unwrap(),
        )
        .await
        .unwrap();
        assert!(
            !companion_column(earlier.companion("blobs").unwrap(), "id").contains(&later_blob.id)
        );
        let later =
            read_authority_act_cut(&db, annotation_event.act.unwrap(), later_event.act.unwrap())
                .await
                .unwrap();
        assert_eq!(
            companion_column(later.companion("blobs").unwrap(), "id"),
            BTreeSet::from([later_blob.id.clone()])
        );
        db.close().await;
    }

    /// A referenced blob that is missing, or present but nonportable, refuses
    /// the whole cut. No production writer can create either state (the
    /// attachment seam always inserts the inline blob first), so this fixture
    /// writes the row directly under a genuinely allocated act.
    #[tokio::test]
    async fn blob_closure_refuses_missing_and_nonportable_blobs() {
        for (blob_id, external) in [("..missing-blob", false), ("..external-blob", true)] {
            let db = fresh_authority().await;
            let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
            let mut alloc = crate::act::ActAllocation::new();
            let act = alloc.get_or_allocate(&mut tx).await.unwrap();
            if external {
                sqlx::query(
                    "INSERT INTO blobs(id,bytes,storage_tier,external_ref,created_at)
                     VALUES(?,NULL,'external','remote://fixture','2026-01-01T00:00:00.000Z')",
                )
                .bind(blob_id)
                .execute(&mut *tx)
                .await
                .unwrap();
            }
            sqlx::query(
                "INSERT INTO content_events
                    (id,record_id,type,payload,actor,created_at,causal_envelope_version,causal_status,act)
                 VALUES(?,?,?,?,NULL,?,1,'complete',?)",
            )
            .bind(format!("act-cut-blob-{blob_id}"))
            .bind("..blob-refusal-target")
            .bind("facet.set")
            .bind(serde_json::json!({ "key": "blob_ref", "value": blob_id }).to_string())
            .bind(crate::store::now_iso())
            .bind(act)
            .execute(&mut *tx)
            .await
            .unwrap();
            tx.commit().await.unwrap();

            let error = read_authority_act_cut(&db, act - 1, act).await.unwrap_err();
            assert!(
                error.to_string().contains("blob"),
                "refusal must name the blob: {error}"
            );
            db.close().await;
        }
    }

    /// Production attestations carry interaction receipts. Invalidating an old
    /// attestation pulls only that attestation and its receipt; an unrelated
    /// old attestation, and the old attestation's out-of-window outputs, stay
    /// out of the cut.
    #[tokio::test]
    async fn provenance_validity_pulls_only_referenced_old_attestation_and_receipt() {
        let db = fresh_authority().await;
        let issuer = crate::provenance::ProvenanceInteractionTokenIssuer::random("host-ui");
        let mut attestations = Vec::new();
        for (index, record_id) in [
            "1a7e4000-0000-4000-8000-0000000000e6",
            "1a7e4000-0000-4000-8000-0000000000e7",
        ]
        .iter()
        .enumerate()
        {
            let arguments = serde_json::json!({
                "name": format!("provenance {index}"),
                "idempotency_key": format!("prov-key-{index}"),
            });
            let scope = crate::provenance::verified_action_scope("create_record", &arguments);
            let token = issuer.issue("local", &scope, 60).unwrap();
            let caller = crate::mcp::Caller::local()
                .with_provenance_interaction_token(&issuer, &token, &scope)
                .unwrap();
            let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
                &caller,
                "create_record",
                &arguments,
                None,
            );
            dispatch
                .scope(append_record(&db, record_id, "provenance"))
                .await;
            attestations.push(dispatch.receipt_ids().pop().unwrap());
        }
        let base = live_head_act(&db).await;

        let mut validity_tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        crate::provenance::append_validity_event_in(
            &mut validity_tx,
            &mut alloc,
            &attestations[0],
            crate::provenance::ValidityChange::Invalidated,
            "act-cut closure",
            "act-cut-closure",
        )
        .await
        .unwrap();
        validity_tx.commit().await.unwrap();

        let cut = read_authority_act_cut(&db, base, base + 1).await.unwrap();
        cut.validate().unwrap();
        let pulled_attestations = companion_column(
            cut.companion("provenance_action_attestations").unwrap(),
            "id",
        );
        assert_eq!(
            pulled_attestations,
            BTreeSet::from([attestations[0].clone()]),
            "only the validity row's attestation is pulled"
        );
        let expected_receipt: Option<String> = sqlx::query_scalar(
            "SELECT interaction_receipt_id FROM provenance_action_attestations WHERE id=?",
        )
        .bind(&attestations[0])
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(
            expected_receipt.is_some(),
            "the production dispatch must carry an interaction receipt"
        );
        assert_eq!(
            companion_column(
                cut.companion("provenance_interaction_receipts").unwrap(),
                "id"
            ),
            BTreeSet::from([expected_receipt.unwrap()]),
            "only the referenced attestation's receipt is pulled"
        );
        assert!(
            cut.companion("provenance_action_outputs")
                .unwrap()
                .rows
                .is_empty(),
            "the old attestation's out-of-window outputs are not pulled"
        );
        assert!(cut
            .companion("provenance_action_events")
            .unwrap()
            .rows
            .is_empty());
        db.close().await;
    }

    /// The legacy `provenance_action_events` output link is a second seed edge
    /// into an attestation, and that attestation's receipt follows it.
    /// Production writers only mint this v1 shape through migration/import, so
    /// the link and its attestations are written directly beneath a real
    /// in-window content event; the unreferenced attestation must stay out.
    #[tokio::test]
    async fn provenance_action_event_pulls_its_attestation_and_receipt() {
        let db = fresh_authority().await;
        let event = append_record_returning(
            &db,
            "1a7e4000-0000-4000-8000-0000000000f1",
            "legacy output link",
        )
        .await;
        let origin = crate::identity::database_id(&db).await.unwrap();
        let hex = |byte: char| byte.to_string().repeat(64);
        sqlx::query(
            "INSERT INTO provenance_interaction_receipts
                (id,schema_version,principal,scope_digest,nonce,verifier,verified_at,evidence_digest)
             VALUES('act-cut-linked-receipt',1,'native/local',?,'nonce-1','host',
                    '2026-01-01T00:00:00.000Z',?)",
        )
        .bind(hex('a'))
        .bind(hex('b'))
        .execute(db.write_pool())
        .await
        .unwrap();
        for (id, receipt) in [
            ("act-cut-linked", Some("act-cut-linked-receipt")),
            ("act-cut-unlinked", None),
        ] {
            sqlx::query(
                "INSERT INTO provenance_action_attestations
                    (id,schema_version,principal,executor_kind,interaction_receipt_id,operation,
                     action_commitment,action_digest,output_event_set_digest,issuer,
                     issuer_origin_database_id,issued_at)
                 VALUES(?,1,'native/local','local',?,'legacy', '{}',?,?,'native-ce',?,
                        '2026-01-01T00:00:01.000Z')",
            )
            .bind(id)
            .bind(receipt)
            .bind(hex('c'))
            .bind(hex('d'))
            .bind(&origin)
            .execute(db.write_pool())
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO provenance_action_events(action_attestation_id,ordinal,output_event_id)
             VALUES('act-cut-linked',0,?)",
        )
        .bind(&event.id)
        .execute(db.write_pool())
        .await
        .unwrap();

        let cut = read_authority_act_cut(&db, event.act.unwrap() - 1, event.act.unwrap())
            .await
            .unwrap();
        cut.validate().unwrap();
        assert_eq!(
            companion_column(
                cut.companion("provenance_action_events").unwrap(),
                "action_attestation_id"
            ),
            BTreeSet::from(["act-cut-linked".to_string()])
        );
        assert_eq!(
            companion_column(
                cut.companion("provenance_action_attestations").unwrap(),
                "id"
            ),
            BTreeSet::from(["act-cut-linked".to_string()]),
            "only the attestation the output link names is pulled"
        );
        assert_eq!(
            companion_column(
                cut.companion("provenance_interaction_receipts").unwrap(),
                "id"
            ),
            BTreeSet::from(["act-cut-linked-receipt".to_string()])
        );
        db.close().await;
    }

    /// The replicated-message chain is produced by the real verified-ingest
    /// path: `content_event_sources` -> `replicated_message_provenance` ->
    /// `destination_message_ingest` -> `replicated_message_references`, keyed
    /// by the in-window source event. A later cut does not leak it backwards.
    #[tokio::test]
    async fn replicated_message_chain_is_carried_from_its_source_event() {
        let db = fresh_authority().await;
        let base = live_head_act(&db).await;
        let result =
            crate::store::ingest_remote_fixture_message(&db, crate::schema::UNFILED_RECORD_ID)
                .await;
        assert_eq!(
            result.status,
            crate::store::IngestStatus::Applied,
            "{}",
            result.code
        );
        let head = live_head_act(&db).await;
        assert_eq!(head, base + 1, "the ingest occupies exactly one act");

        let cut = read_authority_act_cut(&db, base, head).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(companion_row_count(&cut, "content_event_sources"), 1);
        assert_eq!(
            companion_row_count(&cut, "replicated_message_provenance"),
            1
        );
        assert_eq!(companion_row_count(&cut, "destination_message_ingest"), 1);
        assert_eq!(
            companion_row_count(&cut, "replicated_message_references"),
            1
        );

        let source_event_id = result.event_ids[0].clone();
        assert_eq!(
            companion_column(cut.companion("content_event_sources").unwrap(), "event_id"),
            BTreeSet::from([source_event_id.clone()])
        );
        let message_id = companion_column(
            cut.companion("destination_message_ingest").unwrap(),
            "message_id",
        );
        assert_eq!(message_id, BTreeSet::from([result.message_ids[0].clone()]));
        assert_eq!(
            companion_column(
                cut.companion("replicated_message_references").unwrap(),
                "source_message_id"
            ),
            message_id,
            "references follow the selected ingest message id"
        );

        // A cut over a later, unrelated act carries no replicated chain.
        append_record(&db, "1a7e4000-0000-4000-8000-0000000000e8", "after").await;
        let after = live_head_act(&db).await;
        let later = read_authority_act_cut(&db, head, after).await.unwrap();
        assert_eq!(
            companion_row_count(&later, "replicated_message_provenance"),
            0
        );
        assert_eq!(companion_row_count(&later, "destination_message_ingest"), 0);
        assert_eq!(
            companion_row_count(&later, "replicated_message_references"),
            0
        );
        db.close().await;
    }

    /// Relationship federation evidence is one-hop: an in-window assertion
    /// carries its federation row, the attestation its payload names, and that
    /// attestation's outputs. An unreferenced attestation and a later act's
    /// federation state stay out.
    ///
    /// The assertion payload is serialized from the real
    /// [`crate::relationship::RelationshipEventPayload`] /
    /// [`crate::relationship::AssertionCreatedV1`] production shape, so moving
    /// or renaming the top-level `authoring_action_attestation_id` breaks this
    /// test rather than silently changing what the closure selects. Only the
    /// row insert itself is direct: no test-reachable seam can mint a foreign
    /// relationship envelope. A second in-window event carries the same
    /// production payload shape but a non-`assertion.created.v1` `type` column,
    /// pinning the type guard.
    #[tokio::test]
    async fn relationship_federation_evidence_is_carried_one_hop_only() {
        const FOREIGN: &str = "ndb_66666666666666666666666666666666";
        const RELATIONSHIP_ORIGIN: &str = "ndb_77777777777777777777777777777777";
        const LINKED_ATTESTATION: &str = "foreign-att-1";
        const WRONG_TYPE_ATTESTATION: &str = "foreign-att-wrong-type";
        let db = fresh_authority().await;

        let assertion_payload = |relationship_id: &str,
                                 created_event_id: &str,
                                 attestation_id: &str| {
            let assertion = crate::relationship::AssertionCreatedV1 {
                schema_version: 1,
                relationship: crate::relationship::RelationshipCoordinate {
                    relationship_origin_db_id: RELATIONSHIP_ORIGIN.into(),
                    relationship_id: relationship_id.into(),
                    relationship_revision: 1,
                },
                relationship_created_event: crate::relationship::RelationshipEventCoordinate {
                    issuer_origin_db_id: FOREIGN.into(),
                    event_id: created_event_id.into(),
                },
                // The production vocabulary accepts only support/contest.
                stance: "support".into(),
                semantic_claimant: "foreign:alice".into(),
                on_behalf_of: None,
                rationale: None,
                valid_from: None,
                valid_until: None,
                causal_parents: Vec::new(),
                origin_admission: crate::relationship::OriginAdmissionV1::from_legacy_authorization(
                    "source_authorised_support",
                    crate::identity::encode_native_record(
                        RELATIONSHIP_ORIGIN,
                        "5a000000-0000-4000-8000-000000000003",
                    )
                    .unwrap(),
                    "0".repeat(64),
                    attestation_id.to_string(),
                ),
                authoring_action_attestation_id: attestation_id.into(),
            };
            String::from_utf8(crate::canonical_json::canonical_json(
                &crate::relationship::RelationshipEventPayload::AssertionCreated(assertion)
                    .value()
                    .unwrap(),
            ))
            .unwrap()
        };
        let linked_payload = assertion_payload(
            "5a000000-0000-4000-8000-000000000001",
            "5a000000-0000-4000-8000-000000000002",
            LINKED_ATTESTATION,
        );
        let wrong_type_payload = assertion_payload(
            "5a000000-0000-4000-8000-000000000004",
            "5a000000-0000-4000-8000-000000000005",
            WRONG_TYPE_ATTESTATION,
        );

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let act = alloc.get_or_allocate(&mut tx).await.unwrap();
        for (id, stream_id, relationship_id, event_type, payload) in [
            (
                "event-1",
                "stream-1",
                "5a000000-0000-4000-8000-000000000001",
                "assertion.created.v1",
                linked_payload.as_str(),
            ),
            (
                "event-wrong-type",
                "stream-wrong-type",
                "5a000000-0000-4000-8000-000000000004",
                "assertion.invalidated.v1",
                wrong_type_payload.as_str(),
            ),
        ] {
            sqlx::query(
                "INSERT INTO relationship_events
                    (id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
                     relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act)
                 VALUES(?,'assertion',?,1,?,?,?,?,'foreign:alice',?,
                        '2026-01-01T00:00:00.000Z','2026-01-01T00:00:01.000Z',?)",
            )
            .bind(id)
            .bind(stream_id)
            .bind(RELATIONSHIP_ORIGIN)
            .bind(relationship_id)
            .bind(event_type)
            .bind(payload)
            .bind(FOREIGN)
            .bind(act)
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        sqlx::query(
            "INSERT INTO relationship_federation_events
                (issuer_origin_db_id,event_id,fingerprint,source_batch_origin_db_id,envelope_id,
                 authenticated_peer_principal,origin_trust_state,origin_evidence_state,received_at)
             VALUES(?,?,?,?,'env-1','foreign:alice','direct_origin','verified','2026-01-01T00:00:02.000Z')",
        )
        .bind(FOREIGN)
        .bind("event-1")
        .bind("a".repeat(64))
        .bind("ndb_88888888888888888888888888888888")
        .execute(&mut *tx)
        .await
        .unwrap();
        for attestation_id in [
            LINKED_ATTESTATION,
            WRONG_TYPE_ATTESTATION,
            "foreign-att-unreferenced",
        ] {
            sqlx::query(
                "INSERT INTO relationship_foreign_action_attestations
                    (issuer_origin_db_id,attestation_id,schema_version,principal,operation,
                     action_digest,output_event_set_digest,issued_at,canonical_attestation,fingerprint)
                 VALUES(?,?,2,'foreign:alice','relate',?,?, '2026-01-01T00:00:03.000Z','{}',?)",
            )
            .bind(FOREIGN)
            .bind(attestation_id)
            .bind("b".repeat(64))
            .bind("c".repeat(64))
            .bind("d".repeat(64))
            .execute(&mut *tx)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO relationship_foreign_action_outputs
                    (issuer_origin_db_id,attestation_id,ordinal,output_domain,
                     output_event_origin_db_id,output_event_id)
                 VALUES(?,?,0,'relationship',?,?)",
            )
            .bind(FOREIGN)
            .bind(attestation_id)
            .bind(FOREIGN)
            .bind(format!("out-{attestation_id}"))
            .execute(&mut *tx)
            .await
            .unwrap();
        }
        tx.commit().await.unwrap();

        let cut = read_authority_act_cut(&db, act - 1, act).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            companion_column(
                cut.companion("relationship_federation_events").unwrap(),
                "event_id"
            ),
            BTreeSet::from(["event-1".to_string()])
        );
        assert_eq!(
            companion_column(
                cut.companion("relationship_foreign_action_attestations")
                    .unwrap(),
                "attestation_id"
            ),
            BTreeSet::from([LINKED_ATTESTATION.to_string()]),
            "only the assertion.created.v1 payload's top-level attestation id is pulled"
        );
        assert_eq!(
            companion_column(
                cut.companion("relationship_foreign_action_outputs")
                    .unwrap(),
                "attestation_id"
            ),
            BTreeSet::from([LINKED_ATTESTATION.to_string()]),
            "outputs follow the selected attestation only"
        );

        // A later act's federation state is not pulled backwards.
        let mut later_tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut later_alloc = crate::act::ActAllocation::new();
        let later_act = later_alloc.get_or_allocate(&mut later_tx).await.unwrap();
        sqlx::query(
            "INSERT INTO relationship_events
                (id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
                 relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act)
             VALUES('event-2','relationship','stream-2',1,?,?,'relationship.created.v1','{}',
                    'foreign:alice',?,'2026-01-02T00:00:00.000Z','2026-01-02T00:00:01.000Z',?)",
        )
        .bind(RELATIONSHIP_ORIGIN)
        .bind("5a000000-0000-4000-8000-000000000006")
        .bind(FOREIGN)
        .bind(later_act)
        .execute(&mut *later_tx)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO relationship_federation_events
                (issuer_origin_db_id,event_id,fingerprint,source_batch_origin_db_id,envelope_id,
                 authenticated_peer_principal,origin_trust_state,origin_evidence_state,received_at)
             VALUES(?,'event-2',?,?,'env-2','foreign:alice','direct_origin','verified','2026-01-02T00:00:02.000Z')",
        )
        .bind(FOREIGN)
        .bind("e".repeat(64))
        .bind("ndb_88888888888888888888888888888888")
        .execute(&mut *later_tx)
        .await
        .unwrap();
        later_tx.commit().await.unwrap();

        let earlier = read_authority_act_cut(&db, act - 1, act).await.unwrap();
        assert_eq!(
            companion_column(
                earlier.companion("relationship_federation_events").unwrap(),
                "event_id"
            ),
            BTreeSet::from(["event-1".to_string()])
        );
        db.close().await;
    }

    /// The production `manage_links` writer creates a relationship assertion
    /// and issues one action attestation whose outputs are relationship-domain
    /// events. Cutting the command's act must carry exactly that attestation
    /// and its relationship outputs, and a second, unrelated command must not
    /// leak into the first cut.
    #[tokio::test]
    async fn relationship_outputs_pull_only_their_action_attestation() {
        let db = fresh_authority().await;
        let source = append_record_returning(
            &db,
            "1a7e4000-0000-4000-8000-000000000101",
            "relationship source",
        )
        .await;
        let target = append_record_returning(
            &db,
            "1a7e4000-0000-4000-8000-000000000102",
            "relationship target",
        )
        .await;
        let base = live_head_act(&db).await;

        let issuer = crate::provenance::ProvenanceInteractionTokenIssuer::random("host-ui");
        let arguments = serde_json::json!({
            "source_id": source.record_id,
            "target_id": target.record_id,
            "relationship": "relates_to",
        });
        let scope = crate::provenance::verified_action_scope("manage_links", &arguments);
        let token = issuer.issue("local", &scope, 60).unwrap();
        let caller = crate::mcp::Caller::local()
            .with_provenance_interaction_token(&issuer, &token, &scope)
            .unwrap();
        let dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &caller,
            "manage_links",
            &arguments,
            None,
        );
        dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let mut alloc = crate::act::ActAllocation::new();
                crate::relationship::legacy::mutate_from_manage_links_in(
                    &mut tx,
                    &caller,
                    &source.record_id,
                    &target.record_id,
                    "relates_to",
                    None,
                    true,
                    &mut alloc,
                )
                .await
                .unwrap();
                db.commit_content(tx).await.unwrap();
            })
            .await;
        let head = live_head_act(&db).await;
        assert_eq!(head, base + 1, "the manage_links command occupies one act");

        let attestations = dispatch.receipt_ids();
        assert_eq!(
            attestations.len(),
            1,
            "one manage_links command issues one attestation"
        );
        let attestation_id = attestations[0].clone();
        let live_outputs: BTreeSet<String> = sqlx::query_scalar(
            "SELECT output_event_id FROM provenance_action_outputs
              WHERE action_attestation_id=? AND output_domain='relationship'",
        )
        .bind(&attestation_id)
        .fetch_all(db.pool())
        .await
        .unwrap()
        .into_iter()
        .collect();
        assert_eq!(
            live_outputs.len(),
            2,
            "the relationship and assertion events are both outputs"
        );
        let live_domains: Vec<String> = sqlx::query_scalar(
            "SELECT output_domain FROM provenance_action_outputs WHERE action_attestation_id=?",
        )
        .bind(&attestation_id)
        .fetch_all(db.pool())
        .await
        .unwrap();
        assert!(live_domains.iter().all(|domain| domain == "relationship"));

        let cut = read_authority_act_cut(&db, base, head).await.unwrap();
        cut.validate().unwrap();
        assert_eq!(
            companion_column(
                cut.companion("provenance_action_outputs").unwrap(),
                "output_event_id"
            ),
            live_outputs,
            "the cut carries exactly the in-window relationship outputs"
        );
        assert_eq!(
            companion_column(
                cut.companion("provenance_action_attestations").unwrap(),
                "id"
            ),
            BTreeSet::from([attestation_id.clone()]),
            "only the attestation those outputs reference is pulled"
        );
        let expected_receipt: Option<String> = sqlx::query_scalar(
            "SELECT interaction_receipt_id FROM provenance_action_attestations WHERE id=?",
        )
        .bind(&attestation_id)
        .fetch_one(db.pool())
        .await
        .unwrap();
        assert!(
            expected_receipt.is_some(),
            "the verified interaction dispatch must carry a receipt"
        );
        assert_eq!(
            companion_column(
                cut.companion("provenance_interaction_receipts").unwrap(),
                "id"
            ),
            BTreeSet::from([expected_receipt.unwrap()])
        );

        // A second, unrelated command at a later act must not leak backwards.
        let other_source =
            append_record_returning(&db, "1a7e4000-0000-4000-8000-000000000103", "other source")
                .await;
        let other_target =
            append_record_returning(&db, "1a7e4000-0000-4000-8000-000000000104", "other target")
                .await;
        let second_base = live_head_act(&db).await;
        let other_arguments = serde_json::json!({
            "source_id": other_source.record_id,
            "target_id": other_target.record_id,
            "relationship": "relates_to",
        });
        let other_scope =
            crate::provenance::verified_action_scope("manage_links", &other_arguments);
        let other_token = issuer.issue("local", &other_scope, 60).unwrap();
        let other_caller = crate::mcp::Caller::local()
            .with_provenance_interaction_token(&issuer, &other_token, &other_scope)
            .unwrap();
        let other_dispatch = crate::provenance::ProvenanceDispatch::from_caller(
            &other_caller,
            "manage_links",
            &other_arguments,
            None,
        );
        other_dispatch
            .scope(async {
                let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
                let mut alloc = crate::act::ActAllocation::new();
                crate::relationship::legacy::mutate_from_manage_links_in(
                    &mut tx,
                    &other_caller,
                    &other_source.record_id,
                    &other_target.record_id,
                    "relates_to",
                    None,
                    true,
                    &mut alloc,
                )
                .await
                .unwrap();
                db.commit_content(tx).await.unwrap();
            })
            .await;
        let second_head = live_head_act(&db).await;
        let other_attestation = other_dispatch.receipt_ids().pop().unwrap();

        let first_cut = read_authority_act_cut(&db, base, head).await.unwrap();
        assert_eq!(
            companion_column(
                first_cut
                    .companion("provenance_action_attestations")
                    .unwrap(),
                "id"
            ),
            BTreeSet::from([attestation_id]),
            "the later command's attestation is out of the first cut"
        );
        let second_cut = read_authority_act_cut(&db, second_base, second_head)
            .await
            .unwrap();
        assert_eq!(
            companion_column(
                second_cut
                    .companion("provenance_action_attestations")
                    .unwrap(),
                "id"
            ),
            BTreeSet::from([other_attestation]),
            "the second cut carries only its own attestation"
        );
        db.close().await;
    }

    // R3 wire-boundary prerequisite: a real authority act cut's carried
    // `relationship_events` act section and `relationship_federation_events`
    // companion section must decode into exactly the typed inputs the
    // preserved-act replay seam consumes, and refuse everything else.

    const WIRE_LOCAL_ORIGIN: &str = "ndb_55555555555555555555555555555555";
    const WIRE_FOREIGN_ORIGIN: &str = "ndb_66666666666666666666666666666666";

    /// Insert one minimally valid relationship-domain assertion event directly.
    /// The authority cut reader performs no stream CAS or projection, so a
    /// direct row is enough to drive the real act-range section export. The
    /// payload is a production-shaped `assertion.evidence_added.v1` object, so
    /// the wire decoder's payload parse exercises the shared payload validator.
    async fn insert_wire_assertion_event(
        tx: &mut sqlx::Transaction<'static, sqlx::Sqlite>,
        issuer_origin_db_id: &str,
        relationship_origin_db_id: &str,
        relationship_id: &str,
        event_id: &str,
        stream_id: &str,
        act: i64,
    ) {
        sqlx::query(
            "INSERT INTO relationship_events
                (id,stream_kind,stream_id,stream_version,relationship_origin_db_id,
                 relationship_id,type,payload,actor,issuer_origin_db_id,occurred_at,ingested_at,act)
             VALUES(?1,'assertion',?2,1,?3,?4,'assertion.evidence_added.v1',
                    '{\"schema_version\":1,\"evidence_ref\":\"native-evidence:wire\",\"reason\":\"wire\"}',
                    'wire:actor',?5,'2026-01-01T00:00:00.000Z','2026-01-01T00:00:01.000Z',?6)",
        )
        .bind(event_id)
        .bind(stream_id)
        .bind(relationship_origin_db_id)
        .bind(relationship_id)
        .bind(issuer_origin_db_id)
        .bind(act)
        .execute(&mut **tx)
        .await
        .unwrap();
    }

    /// A real authority cut carrying two acts: a local assertion pair in act 1
    /// and a federated assertion event plus its receiver-local federation
    /// evidence in act 2. The federation companion is reachable only through
    /// the carried federated event, exactly as the closure derives it.
    async fn relationship_wire_cut() -> (crate::Db, AuthorityActCut, i64, String) {
        let db = fresh_authority().await;
        let local_relationship_id = "5a000000-0000-4000-8000-000000000001";
        let foreign_event_id = "6a000000-0000-4000-8000-000000000001";

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let local_act = alloc.get_or_allocate(&mut tx).await.unwrap();
        for (event_id, stream_id) in [
            (
                "5a000000-0000-4000-8000-000000000003",
                "5a000000-0000-4000-8000-000000000004",
            ),
            (
                "5a000000-0000-4000-8000-000000000005",
                "5a000000-0000-4000-8000-000000000006",
            ),
        ] {
            insert_wire_assertion_event(
                &mut tx,
                WIRE_LOCAL_ORIGIN,
                WIRE_LOCAL_ORIGIN,
                local_relationship_id,
                event_id,
                stream_id,
                local_act,
            )
            .await;
        }
        tx.commit().await.unwrap();

        let mut tx = crate::db::begin_write(db.write_pool()).await.unwrap();
        let mut alloc = crate::act::ActAllocation::new();
        let foreign_act = alloc.get_or_allocate(&mut tx).await.unwrap();
        insert_wire_assertion_event(
            &mut tx,
            WIRE_FOREIGN_ORIGIN,
            WIRE_FOREIGN_ORIGIN,
            "5a000000-0000-4000-8000-000000000007",
            foreign_event_id,
            "6a000000-0000-4000-8000-000000000002",
            foreign_act,
        )
        .await;
        sqlx::query(
            "INSERT INTO relationship_federation_events
                (issuer_origin_db_id,event_id,fingerprint,source_batch_origin_db_id,envelope_id,
                 authenticated_peer_principal,origin_trust_state,origin_evidence_state,received_at)
             VALUES(?1,?2,?3,'ndb_88888888888888888888888888888888','env-wire',
                    'wire:peer','direct_origin','verified','2026-01-01T00:00:02.000Z')",
        )
        .bind(WIRE_FOREIGN_ORIGIN)
        .bind(foreign_event_id)
        .bind("a".repeat(64))
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        let head = live_head_act(&db).await;
        assert_eq!(head, foreign_act, "the federated act is the authority head");
        let cut = read_authority_act_cut(&db, 0, head).await.unwrap();
        cut.validate().unwrap();
        (db, cut, head, foreign_event_id.to_string())
    }

    fn wire_event_section(cut: &AuthorityActCut) -> Section {
        cut.section("relationship_events").unwrap().clone()
    }

    fn wire_federation_section(cut: &AuthorityActCut) -> Section {
        cut.companion("relationship_federation_events")
            .unwrap()
            .clone()
    }

    fn column_position(section: &Section, name: &str) -> usize {
        section
            .columns
            .iter()
            .position(|column| column.name == name)
            .unwrap_or_else(|| panic!("section has no {name} column"))
    }

    /// The real cut's two carried sections decode to exactly the bounded
    /// reader's / full reader's typed rows, and the carried federation
    /// companion decodes to exactly the expected federated identity set.
    #[tokio::test]
    async fn carried_relationship_sections_decode_to_exact_replay_inputs() {
        let (db, cut, head, foreign_event_id) = relationship_wire_cut().await;

        let decoded =
            crate::relationship::relationship_replay_events_from_section(&wire_event_section(&cut))
                .unwrap();

        let mut conn = db.write_pool().acquire().await.unwrap();
        let bounded = crate::relationship::relationship_events_in_act_range(&mut conn, 0, head)
            .await
            .unwrap();
        let full = crate::relationship::read_all_relationship_events(&mut conn)
            .await
            .unwrap();
        drop(conn);

        assert_eq!(
            decoded, bounded,
            "decoded wire rows must equal the bounded act-range reader"
        );
        assert_eq!(
            decoded, full,
            "every fixture row is stamped inside the cut, so the full reader agrees"
        );
        assert!(
            decoded.iter().all(|event| event.act.is_some()),
            "a live (F1, F2] authority cut carries only act-stamped rows"
        );
        assert_eq!(decoded.len(), 3, "two local rows and one federated row");

        let identities = crate::relationship::relationship_federation_identities_from_section(
            &wire_federation_section(&cut),
            &decoded,
        )
        .unwrap();
        assert_eq!(
            identities,
            BTreeSet::from([(WIRE_FOREIGN_ORIGIN.to_string(), foreign_event_id)])
        );
        db.close().await;
    }

    /// Every malformed carried section refuses before it can supply a typed
    /// input: wrong identity, format, revision, columns, primary key, cell
    /// storage class, NULL in a required column, or malformed payload JSON.
    #[tokio::test]
    async fn relationship_wire_decoder_refuses_wrong_identity_columns_and_cells() {
        let (db, cut, _head, _foreign_event_id) = relationship_wire_cut().await;
        let baseline = wire_event_section(&cut);
        let decode = crate::relationship::relationship_replay_events_from_section;
        assert!(
            decode(&baseline).is_ok(),
            "the real cut section must decode"
        );

        let mut wrong_name = baseline.clone();
        wrong_name.name = "not_relationship_events".into();
        assert!(decode(&wrong_name).is_err(), "wrong table name");

        let mut wrong_format = baseline.clone();
        wrong_format.format = "native.canonical-interchange.section.v0".into();
        assert!(decode(&wrong_format).is_err(), "wrong section format");

        let mut wrong_revision = baseline.clone();
        wrong_revision.revision = 4;
        assert!(decode(&wrong_revision).is_err(), "wrong section revision");

        let mut reordered = baseline.clone();
        reordered.columns.swap(1, 2);
        assert!(decode(&reordered).is_err(), "wrong column order");

        let mut retyped = baseline.clone();
        retyped.columns[column_position(&baseline, "stream_version")].declared_type = "TEXT".into();
        assert!(decode(&retyped).is_err(), "wrong declared column type");

        let mut wrong_pk = baseline.clone();
        wrong_pk.primary_key = vec!["id".into()];
        assert!(decode(&wrong_pk).is_err(), "wrong primary key");

        let actor = column_position(&baseline, "actor");
        let mut integer_actor = baseline.clone();
        integer_actor.rows[0][actor] = Cell::Integer(1);
        assert!(
            decode(&integer_actor).is_err(),
            "wrong storage class for a required text column"
        );

        let act = column_position(&baseline, "act");
        let mut text_act = baseline.clone();
        text_act.rows[0][act] = Cell::Text("1".into());
        assert!(
            decode(&text_act).is_err(),
            "wrong storage class for the act column"
        );

        let mut null_actor = baseline.clone();
        null_actor.rows[0][actor] = Cell::Null;
        assert!(
            decode(&null_actor).is_err(),
            "NULL in a required NOT NULL text column"
        );

        let payload = column_position(&baseline, "payload");
        let mut bad_payload = baseline.clone();
        bad_payload.rows[0][payload] = Cell::Text("{".into());
        assert!(decode(&bad_payload).is_err(), "malformed payload JSON");

        // A structurally valid section whose payload does not match its `type`
        // is refused by the shared payload validator, not silently accepted.
        let mut wrong_payload_shape = baseline.clone();
        wrong_payload_shape.rows[0][payload] = Cell::Text("{}".into());
        assert!(
            decode(&wrong_payload_shape).is_err(),
            "payload that does not match the declared event type"
        );

        // A legacy NULL act is legal in a directly constructed current-revision
        // section and must round-trip exactly as `None`.
        let mut legacy = baseline.clone();
        legacy.rows[0][act] = Cell::Null;
        let decoded = decode(&legacy).unwrap();
        assert!(
            decoded[0].act.is_none(),
            "a legacy NULL act must decode as None"
        );
        assert!(
            decoded[1..].iter().all(|event| event.act.is_some()),
            "only the explicitly nulled row loses its act"
        );
        db.close().await;
    }

    /// The federation companion decoder pins identity/columns/PK and refuses
    /// wrong cell kinds, duplicate identities, and identities that name no
    /// carried relationship event.
    #[tokio::test]
    async fn federation_wire_decoder_refuses_wrong_columns_duplicates_and_unknown_rows() {
        let (db, cut, _head, _foreign_event_id) = relationship_wire_cut().await;
        let decoded =
            crate::relationship::relationship_replay_events_from_section(&wire_event_section(&cut))
                .unwrap();
        let federation = wire_federation_section(&cut);
        let decode = crate::relationship::relationship_federation_identities_from_section;
        assert!(
            decode(&federation, &decoded).is_ok(),
            "the real companion must decode"
        );

        let mut wrong_name = federation.clone();
        wrong_name.name = "not_relationship_federation_events".into();
        assert!(decode(&wrong_name, &decoded).is_err(), "wrong table name");

        let mut wrong_pk = federation.clone();
        wrong_pk.primary_key = vec!["event_id".into()];
        assert!(decode(&wrong_pk, &decoded).is_err(), "wrong primary key");

        let issuer = column_position(&federation, "issuer_origin_db_id");
        let mut integer_issuer = federation.clone();
        integer_issuer.rows[0][issuer] = Cell::Integer(1);
        assert!(
            decode(&integer_issuer, &decoded).is_err(),
            "wrong storage class for an identity column"
        );

        let mut duplicate = federation.clone();
        duplicate.rows.push(duplicate.rows[0].clone());
        assert!(
            decode(&duplicate, &decoded).is_err(),
            "duplicate federation identity"
        );

        let event = column_position(&federation, "event_id");
        let mut unknown_identity = federation.clone();
        unknown_identity.rows[0][event] = Cell::Text("00000000-0000-4000-8000-000000000000".into());
        assert!(
            decode(&unknown_identity, &decoded).is_err(),
            "identity that names no carried relationship event"
        );

        assert!(
            decode(&federation, &[]).is_err(),
            "every identity must name a carried event"
        );
        db.close().await;
    }
}
