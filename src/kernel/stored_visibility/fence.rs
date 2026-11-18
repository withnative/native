//! The Level 0 trust check (design 73ad275 §5, rev 2.1 #2; slice 2b.1).
//!
//! A stored row may be trusted only when, in the reader's own snapshot:
//!
//! * the object set is exactly the compiled one and marking is on;
//! * a `live` generation exists whose marking era and epoch equal
//!   `p_marking`'s;
//! * that generation's state row for the family was built by this binary's
//!   derivation version and fingerprint, and is ready;
//! * no dirty key of a kind the family depends on (or of an unknown kind)
//!   exists at all (the coarse fence).
//!
//! Any failure means the oracle answers. No production read calls this yet.

// No production caller yet (slice 2b.1 is test-only; scheduling is 2b.5).
#![cfg_attr(not(test), allow(dead_code))]

use super::*;

/// Why a stored row is not trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Untrusted {
    Absent,
    Drifted,
    MarkingOff,
    NoLiveGeneration,
    Era,
    Epoch,
    /// The family's state row is missing or was built by another version or
    /// fingerprint.
    State,
    NotReady,
    Dirty,
    /// The demanded key has no stored row (HomeAnchor: not a rooted home;
    /// Principal: not a `kernel_principals` principal; or not yet derived).
    /// Never read as a stored value.
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Trust {
    Trusted { generation: i64 },
    Untrusted(Untrusted),
}

#[derive(sqlx::FromRow)]
struct LiveGeneration {
    generation: i64,
    marking_since_seq: i64,
    invalidation_epoch: i64,
}

/// The family-wide checks, in the caller's transaction (one snapshot).
pub(crate) async fn level0_trust_on(conn: &mut SqliteConnection, family: Family) -> Result<Trust> {
    require_transaction(conn, "trust check")?;
    let untrusted = |reason| Ok(Trust::Untrusted(reason));
    match object_state_on(conn).await? {
        ObjectState::Absent => return untrusted(Untrusted::Absent),
        ObjectState::Drifted => return untrusted(Untrusted::Drifted),
        ObjectState::Exact => {}
    }
    let Some(marking) = marking_row_on(conn).await? else {
        return untrusted(Untrusted::Drifted);
    };
    if !marking.enabled {
        return untrusted(Untrusted::MarkingOff);
    }
    let live: Vec<LiveGeneration> = sqlx::query_as(
        "SELECT generation, marking_since_seq, invalidation_epoch FROM main.p_generation WHERE role = 'live'",
    )
    .fetch_all(&mut *conn)
    .await?;
    let [live] = live.as_slice() else {
        return untrusted(Untrusted::NoLiveGeneration);
    };
    if live.marking_since_seq != marking.marking_since_seq {
        return untrusted(Untrusted::Era);
    }
    if live.invalidation_epoch != marking.invalidation_epoch {
        return untrusted(Untrusted::Epoch);
    }
    let state: Option<(i64, String, bool)> = sqlx::query_as(
        "SELECT derivation_version, fingerprint, ready FROM main.p_state WHERE generation = ? AND family = ?",
    )
    .bind(live.generation)
    .bind(family.as_str())
    .fetch_optional(&mut *conn)
    .await?;
    let Some((version, fingerprint, ready)) = state else {
        return untrusted(Untrusted::State);
    };
    if version != family.derivation_version() || fingerprint != family.fingerprint() {
        return untrusted(Untrusted::State);
    }
    if !ready {
        return untrusted(Untrusted::NotReady);
    }
    if dirty_for_on(conn, family).await? {
        return untrusted(Untrusted::Dirty);
    }
    Ok(Trust::Trusted {
        generation: live.generation,
    })
}

/// The first dirty kind, and the next kind after a given one. Each is a seek
/// on the `(kind, key)` primary key that skips every key of the kinds
/// before it, however many there are.
pub(super) const FIRST_KIND_SQL: &str = "SELECT kind FROM main.p_dirty ORDER BY kind LIMIT 1";
pub(super) const NEXT_KIND_SQL: &str =
    "SELECT kind FROM main.p_dirty WHERE kind > ?1 ORDER BY kind LIMIT 1";

/// Is any key dirty that the family depends on, or of a kind this binary
/// does not know? Walks the distinct dirty kinds by index seeks: each known
/// kind the family ignores is visited once and skipped as a range, so the
/// probe costs at most one seek per supported kind plus one, never one per
/// irrelevant key.
async fn dirty_for_on(conn: &mut SqliteConnection, family: Family) -> Result<bool> {
    let mut kind: Option<String> = sqlx::query_scalar(FIRST_KIND_SQL)
        .fetch_optional(&mut *conn)
        .await?;
    for _ in 0..=KeyKind::ALL.len() {
        let Some(current) = kind else {
            return Ok(false);
        };
        match KeyKind::ALL.into_iter().find(|k| k.as_str() == current) {
            Some(known) if !family.depends_on().contains(&known) => {}
            // A dependent kind, or one this binary does not know.
            _ => return Ok(true),
        }
        kind = sqlx::query_scalar(NEXT_KIND_SQL)
            .bind(&current)
            .fetch_optional(&mut *conn)
            .await?;
    }
    // Unreachable with distinct known kinds; anything else is untrusted.
    Ok(true)
}

/// A demanded home's stored anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HomeAnchorLookup {
    /// The stored value: `None` is a broken rooted walk (the live gate fails
    /// closed for it), never an absent row.
    Trusted {
        anchor: Option<String>,
    },
    Untrusted(Untrusted),
}

/// The lookup contract for one demanded home, in the caller's transaction:
/// the family checks, then the row. Only rooted homes are materialized, so a
/// home without a row is `Untrusted(Missing)` and the oracle answers; an
/// absent row never becomes a trusted NULL anchor or a trusted no-view.
pub(crate) async fn home_anchor_lookup_on(
    conn: &mut SqliteConnection,
    home: &str,
) -> Result<HomeAnchorLookup> {
    let generation = match level0_trust_on(conn, Family::HomeAnchor).await? {
        Trust::Trusted { generation } => generation,
        Trust::Untrusted(reason) => return Ok(HomeAnchorLookup::Untrusted(reason)),
    };
    let row: Option<Option<String>> = sqlx::query_scalar(
        "SELECT anchor FROM main.p_home_anchor WHERE generation = ? AND home = ?",
    )
    .bind(generation)
    .bind(home)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        Some(anchor) => HomeAnchorLookup::Trusted { anchor },
        None => HomeAnchorLookup::Untrusted(Untrusted::Missing),
    })
}

/// A caller's stored admission and transform flag (spike B X6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PrincipalLookup {
    Trusted { admitted: bool, transform: bool },
    Untrusted(Untrusted),
}

/// The lookup contract for one caller, in the caller's transaction: the
/// family checks, then the row. Only `kernel_principals` principals are
/// materialized, so a roster-only, unknown or anonymous caller has no row
/// and is `Untrusted(Missing)`: the oracle answers, never a stored default.
pub(crate) async fn principal_lookup_on(
    conn: &mut SqliteConnection,
    principal: &str,
) -> Result<PrincipalLookup> {
    let generation = match level0_trust_on(conn, Family::Principal).await? {
        Trust::Trusted { generation } => generation,
        Trust::Untrusted(reason) => return Ok(PrincipalLookup::Untrusted(reason)),
    };
    let row: Option<(bool, bool)> = sqlx::query_as(
        "SELECT admitted, transform FROM main.p_principal WHERE generation = ? AND principal = ?",
    )
    .bind(generation)
    .bind(principal)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        Some((admitted, transform)) => PrincipalLookup::Trusted {
            admitted,
            transform,
        },
        None => PrincipalLookup::Untrusted(Untrusted::Missing),
    })
}

pub(crate) use super::derive::Access;

/// A principal's stored access at one policy anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ScopeAccessLookup {
    Trusted(Access),
    Untrusted(Untrusted),
}

/// The lookup contract for one (principal, anchor) pair, in the caller's
/// transaction: the family checks, then the row. A pair without a row (a
/// new principal or anchor since the last rebuild, or never derived) is
/// `Untrusted(Missing)`: the oracle answers, never "valid without view".
/// HomeAnchor and Principal are separate lookups; nothing here composes
/// them into a gate.
pub(crate) async fn scope_access_lookup_on(
    conn: &mut SqliteConnection,
    principal: &str,
    anchor: &str,
) -> Result<ScopeAccessLookup> {
    let generation = match level0_trust_on(conn, Family::ScopeAccess).await? {
        Trust::Trusted { generation } => generation,
        Trust::Untrusted(reason) => return Ok(ScopeAccessLookup::Untrusted(reason)),
    };
    let row: Option<i64> = sqlx::query_scalar(
        "SELECT access FROM main.p_scope_access WHERE generation = ? AND principal = ? AND anchor = ?",
    )
    .bind(generation)
    .bind(principal)
    .bind(anchor)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(match row {
        Some(code) => match Access::from_code(code) {
            Some(access) => ScopeAccessLookup::Trusted(access),
            None => ScopeAccessLookup::Untrusted(Untrusted::Drifted),
        },
        None => ScopeAccessLookup::Untrusted(Untrusted::Missing),
    })
}
