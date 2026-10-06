//! Conformance — the executable spine contract (task 33e5aab, critical-path
//! step 2). One entry point, [`run_conformance`], validates a native-ce database
//! against the FROZEN v1 contract (`crate::schema::contract`) and reports
//! violations; the CLI (`cargo run --bin conformance`) exits non-zero on any.
//!
//! The suite is the contract's enforcement mechanism, layered as:
//!   - frozen-ddl — this build's DDL still hashes to the frozen pin (an edited
//!     schema is a contract revision, not a diff)
//!   - spine checks — closed types, TYPE IMMUTABILITY, open kind, 4 spine
//!     facets, 9 spine relationships, substrate boundary (`spine`).
//!     `closed-types` and `type-immutability` are deliberately separate lines:
//!     the first asserts a record's type is one of the 10 (a CHECK constraint),
//!     the second that it stays the one it was (a property of the fold, since
//!     no DDL constraint can express it)
//!   - rebuild-and-diff — replay the CONTENT log into a fresh database and
//!     require projection equality (`rebuild`); drift between log and
//!     projections is a violation
//!   - rebuild-and-diff-meta — the same, on the META log (ba9f97e).
//!   - rebuild-and-diff-policy — the independent policy log and fold.
//!   - rebuild-and-diff-relationship — the independent relationship/assertion
//!     log plus receiver-local admission and effective graph fold.
//!   - rebuild-and-diff-control — the independent instruction-control log and
//!     fold.
//!   - rebuild-and-diff-derivation — the independent product-neutral derivation
//!     log and its stable series, immutable revision/manifest, failed-attempt,
//!     and application-marker projections. Six logs, six folds, six
//!     conformance checks: the symmetry is the point, since the
//!     meta tier's history was previously half-built and had no check at all
//!   - rebuild-and-diff-control — the independent portable instruction/control
//!     log and its synchronous projections
//!   - read-log-disposability — the read log is a TAP, not infrastructure
//!     (fbfaf25 §6). Differential rather than a survival test: drop both
//!     read-log tables and every behavioral tool must answer IDENTICALLY,
//!     apart from explicitly enumerated response exemptions. `describe_schema`
//!     is excluded because it mirrors the physical drop rather than consuming
//!     the log; "still functions" is free under fail-open and proves nothing
//!   - authorization-revision-state — the schema-12 cache fence has exactly one
//!     valid singleton row and the exact complete frozen security-trigger set;
//!     missing, modified, no-op, or additional reserved triggers fail.

pub mod read_log;
pub mod rebuild;
pub mod spine;

pub use read_log::*;
pub use rebuild::*;
pub use spine::*;

use crate::db::Db;
use crate::schema::{ddl_sha256, FROZEN_DDL_SHA256};

/// Explicit verification selection. Existing entry points always use FULL.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConformanceProfile {
    #[default]
    Full,
    /// Retains release-blocking invariants, deferring historical comparisons
    /// and the synthetic read-log qualification fixture.
    #[serde(rename = "production-release")]
    Core,
}

/// Sorted canonical IDs omitted by CORE (`production-release` in portable receipts).
pub const PRODUCTION_RELEASE_DEFERRED_CHECKS: &[&str] = &[
    "read-log-disposability",
    "rebuild-and-diff",
    "rebuild-and-diff-control",
    "rebuild-and-diff-derivation",
    "rebuild-and-diff-meta",
    "rebuild-and-diff-policy",
    "rebuild-and-diff-relationship",
    "relationship-event-log-state",
];

impl ConformanceProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Core => "production-release",
        }
    }

    pub fn deferred_checks(self) -> &'static [&'static str] {
        match self {
            Self::Full => &[],
            Self::Core => PRODUCTION_RELEASE_DEFERRED_CHECKS,
        }
    }
}

impl std::fmt::Display for ConformanceProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::str::FromStr for ConformanceProfile {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "full" => Ok(Self::Full),
            "production-release" => Ok(Self::Core),
            _ => Err("verification profile must be full or production-release"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConformanceReport {
    pub ok: bool,
    pub checks: Vec<CheckResult>,
    /// None identifies the separate observational standby admission suite;
    /// that suite is neither FULL nor CORE.
    pub profile: Option<ConformanceProfile>,
    pub deferred_checks: Vec<String>,
    /// Static check names and durations only; never database rows.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub check_timings: Vec<ConformanceCheckTiming>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConformanceCheckTiming {
    pub check: String,
    pub elapsed_ms: u128,
}

/// The freeze check: the DDL compiled into this build must hash to the pinned
/// frozen fingerprint. This binds the running code (not just the database under
/// test) to the contract — successor artifacts derive from the frozen DDL, so
/// silently editing it must fail conformance until it is deliberately re-frozen.
pub fn check_frozen_ddl() -> CheckResult {
    let actual = ddl_sha256();
    let ok = actual == FROZEN_DDL_SHA256;
    CheckResult {
        check: "frozen-ddl".into(),
        ok,
        violations: if ok {
            vec![]
        } else {
            vec![format!(
                "DDL no longer matches the current build fingerprint (expected {FROZEN_DDL_SHA256}, got {actual}) — schema edits require a deliberate re-freeze of schema/contract.rs and re-derivation of successor artifacts"
            )]
        },
    }
}

/// The content rebuild-and-diff drift check, adapted into the suite's report
/// shape.
pub async fn check_rebuild_and_diff(db: &Db) -> CheckResult {
    into_check("rebuild-and-diff", rebuild_and_diff(db).await)
}

/// The META rebuild-and-diff drift check (ba9f97e) — the same check, on the
/// other log. Reported as its own line rather than folded into the content one:
/// a tier that shares its neighbour's pass/fail signal is a tier whose own drift
/// can hide behind the neighbour being green.
pub async fn check_rebuild_and_diff_meta(db: &Db) -> CheckResult {
    into_check("rebuild-and-diff-meta", rebuild_and_diff_meta(db).await)
}

pub async fn check_rebuild_and_diff_policy(db: &Db) -> CheckResult {
    into_check("rebuild-and-diff-policy", rebuild_and_diff_policy(db).await)
}

pub async fn check_rebuild_and_diff_relationship(db: &Db) -> CheckResult {
    into_check(
        "rebuild-and-diff-relationship",
        rebuild_and_diff_relationship(db).await,
    )
}

pub async fn check_rebuild_and_diff_control(db: &Db) -> CheckResult {
    into_check(
        "rebuild-and-diff-control",
        rebuild_and_diff_control(db).await,
    )
}

pub async fn check_rebuild_and_diff_derivation(db: &Db) -> CheckResult {
    into_check(
        "rebuild-and-diff-derivation",
        rebuild_and_diff_derivation(db).await,
    )
}

/// The grant-only realtime revision is safe only while its singleton and
/// every grant-shaped trigger remain intact: a missing bump would suppress a
/// revocation prompt the stream owes its subscribers.
pub async fn check_grant_revision_state(db: &Db) -> CheckResult {
    match crate::authorization_grant::state_violations(db).await {
        Ok(violations) => CheckResult {
            check: "grant-revision-state".into(),
            ok: violations.is_empty(),
            violations,
        },
        Err(err) => CheckResult {
            check: "grant-revision-state".into(),
            ok: false,
            violations: vec![format!(
                "grant revision state could not be validated: {err}"
            )],
        },
    }
}

/// The authorization-dependent rollup cache is safe only while the schema-12
/// singleton and every frozen security-input trigger remain intact.
pub async fn check_authorization_revision_state(db: &Db) -> CheckResult {
    match crate::authorization_revision::state_violations(db).await {
        Ok(violations) => CheckResult {
            check: "authorization-revision-state".into(),
            ok: violations.is_empty(),
            violations,
        },
        Err(err) => CheckResult {
            check: "authorization-revision-state".into(),
            ok: false,
            violations: vec![format!(
                "authorization revision state could not be validated: {err}"
            )],
        },
    }
}

pub async fn check_provenance_state(db: &Db) -> CheckResult {
    match crate::provenance::state_violations(db).await {
        Ok(violations) => CheckResult {
            check: "provenance-state".into(),
            ok: violations.is_empty(),
            violations,
        },
        Err(error) => CheckResult {
            check: "provenance-state".into(),
            ok: false,
            violations: vec![format!("provenance state could not be validated: {error}")],
        },
    }
}

fn into_check(name: &str, result: crate::error::Result<RebuildDiffResult>) -> CheckResult {
    // A malformed database (broken event log, unreplayable events) must surface
    // as a violation, not crash the suite.
    let result = match result {
        Ok(result) => result,
        Err(err) => {
            return CheckResult {
                check: name.into(),
                ok: false,
                violations: vec![format!("event log could not be replayed: {err}")],
            };
        }
    };
    let violations: Vec<String> = result
        .tables
        .iter()
        .filter(|t| !t.mismatches.is_empty() || t.live != t.rebuilt)
        .map(|t| {
            format!(
                "projection drift in '{}' (live {} rows, rebuilt {}): {}",
                t.table,
                t.live,
                t.rebuilt,
                t.mismatches
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        })
        .collect();
    CheckResult {
        check: name.into(),
        ok: result.equal,
        violations,
    }
}

/// Run the full conformance suite against a database.
pub async fn run_conformance(db: &Db) -> ConformanceReport {
    run_conformance_with_progress(db, |_, _| {}).await
}

/// The full suite with aggregate-only progress: `None` marks a named check's
/// start and `Some(ms)` marks completion. A cancelled run still identifies its
/// last active check without exposing any data from the database.
pub(crate) async fn run_conformance_with_progress(
    db: &Db,
    on_check: impl FnMut(&str, Option<u128>),
) -> ConformanceReport {
    run_conformance_with_profile_and_progress(db, ConformanceProfile::Full, on_check).await
}

/// Select a verification profile explicitly; [`run_conformance`] remains FULL.
pub async fn run_conformance_with_profile(
    db: &Db,
    profile: ConformanceProfile,
) -> ConformanceReport {
    run_conformance_with_profile_and_progress(db, profile, |_, _| {}).await
}

pub(crate) async fn run_conformance_with_profile_and_progress(
    db: &Db,
    profile: ConformanceProfile,
    mut on_check: impl FnMut(&str, Option<u128>),
) -> ConformanceReport {
    let mut check_timings = Vec::new();
    macro_rules! timed {
        ($name:literal, $check:expr) => {{
            on_check($name, None);
            let started = std::time::Instant::now();
            let result = $check;
            let elapsed_ms = started.elapsed().as_millis();
            check_timings.push(ConformanceCheckTiming {
                check: $name.into(),
                elapsed_ms,
            });
            on_check($name, Some(elapsed_ms));
            result
        }};
    }
    let mut checks: Vec<CheckResult> = vec![timed!("frozen-ddl", check_frozen_ddl())];
    checks.extend(
        run_spine_checks_with_progress(db, &mut |name, elapsed| {
            if let Some(elapsed_ms) = elapsed {
                check_timings.push(ConformanceCheckTiming {
                    check: name.into(),
                    elapsed_ms,
                });
            }
            on_check(name, elapsed);
        })
        .await,
    );
    if profile == ConformanceProfile::Full {
        checks.push(timed!("rebuild-and-diff", check_rebuild_and_diff(db).await));
        checks.push(timed!(
            "rebuild-and-diff-meta",
            check_rebuild_and_diff_meta(db).await
        ));
        checks.push(timed!(
            "rebuild-and-diff-policy",
            check_rebuild_and_diff_policy(db).await
        ));
        checks.push(timed!(
            "rebuild-and-diff-relationship",
            check_rebuild_and_diff_relationship(db).await
        ));
        checks.push(timed!(
            "rebuild-and-diff-control",
            check_rebuild_and_diff_control(db).await
        ));
        checks.push(timed!(
            "rebuild-and-diff-derivation",
            check_rebuild_and_diff_derivation(db).await
        ));
    }
    checks.push(timed!("provenance-state", check_provenance_state(db).await));
    if profile == ConformanceProfile::Full {
        checks.push(timed!(
            "read-log-disposability",
            check_read_log_disposability().await
        ));
    }
    checks.push(timed!(
        "authorization-revision-state",
        check_authorization_revision_state(db).await
    ));
    checks.push(timed!(
        "grant-revision-state",
        check_grant_revision_state(db).await
    ));
    checks.push(timed!(
        "authorization-policy-state",
        match crate::authorization::state_violations(db).await {
            Ok(violations) => CheckResult {
                check: "authorization-policy-state".into(),
                ok: violations.is_empty(),
                violations,
            },
            Err(err) => CheckResult {
                check: "authorization-policy-state".into(),
                ok: false,
                violations: vec![format!("authorization state could not be validated: {err}")],
            },
        }
    ));
    checks.push(timed!(
        "control-event-log-state",
        match crate::control::state_violations(db).await {
            Ok(violations) => CheckResult {
                check: "control-event-log-state".into(),
                ok: violations.is_empty(),
                violations,
            },
            Err(err) => CheckResult {
                check: "control-event-log-state".into(),
                ok: false,
                violations: vec![format!(
                    "instruction control event log state could not be validated: {err}"
                )],
            },
        }
    ));
    checks.push(timed!(
        "policy-event-log-state",
        match crate::policy::state_violations(db).await {
            Ok(violations) => CheckResult {
                check: "policy-event-log-state".into(),
                ok: violations.is_empty(),
                violations,
            },
            Err(err) => CheckResult {
                check: "policy-event-log-state".into(),
                ok: false,
                violations: vec![format!("policy event log could not be validated: {err}")],
            },
        }
    ));
    if profile == ConformanceProfile::Full {
        checks.push(timed!(
            "relationship-event-log-state",
            match crate::relationship::relationship_state_violations(db).await {
                Ok(violations) => CheckResult {
                    check: "relationship-event-log-state".into(),
                    ok: violations.is_empty(),
                    violations,
                },
                Err(err) => CheckResult {
                    check: "relationship-event-log-state".into(),
                    ok: false,
                    violations: vec![format!(
                        "relationship event log could not be validated: {err}"
                    )],
                },
            }
        ));
    } else {
        checks.push(timed!(
            "relationship-append-only-triggers",
            match crate::relationship::relationship_append_only_trigger_violations(db).await {
                Ok(violations) => CheckResult {
                    check: "relationship-append-only-triggers".into(),
                    ok: violations.is_empty(),
                    violations,
                },
                Err(err) => CheckResult {
                    check: "relationship-append-only-triggers".into(),
                    ok: false,
                    violations: vec![format!(
                        "relationship triggers could not be validated: {err}"
                    )],
                },
            }
        ));
    }
    checks.push(timed!(
        "portable-identity-state",
        match crate::identity::state_violations(db).await {
            Ok(violations) => CheckResult {
                check: "portable-identity-state".into(),
                ok: violations.is_empty(),
                violations,
            },
            Err(err) => CheckResult {
                check: "portable-identity-state".into(),
                ok: false,
                violations: vec![format!(
                    "portable identity state could not be validated: {err}"
                )],
            },
        }
    ));
    ConformanceReport {
        ok: checks.iter().all(|c| c.ok),
        checks,
        profile: Some(profile),
        deferred_checks: profile
            .deferred_checks()
            .iter()
            .map(|name| (*name).into())
            .collect(),
        check_timings,
    }
}

/// Candidate-data admission suite for immutable standby snapshots.
///
/// Unlike [`run_conformance`], every check here is observational with respect
/// to `db`: write probes, the compiled-DDL self-check, and the unrelated
/// read-log fixture are deliberately excluded. Rebuild checks write only their
/// fresh in-memory projections.
pub(crate) async fn run_standby_admission_conformance(db: &Db) -> ConformanceReport {
    run_standby_admission_conformance_with_progress(db, |_, _| {}).await
}

/// Same start/elapsed semantics as the full suite. Completion means the check
/// returned, not that it passed; only the final report establishes suite success.
pub(crate) async fn run_standby_admission_conformance_with_progress(
    db: &Db,
    mut on_check: impl FnMut(&str, Option<u128>),
) -> ConformanceReport {
    fn guarded(name: &str, result: crate::error::Result<CheckResult>) -> CheckResult {
        match result {
            Ok(check) => check,
            Err(error) => CheckResult {
                check: name.into(),
                ok: false,
                violations: vec![format!("check could not run: {error}")],
            },
        }
    }
    fn state(name: &str, result: crate::error::Result<Vec<String>>) -> CheckResult {
        match result {
            Ok(violations) => CheckResult {
                check: name.into(),
                ok: violations.is_empty(),
                violations,
            },
            Err(error) => CheckResult {
                check: name.into(),
                ok: false,
                violations: vec![format!("state could not be validated: {error}")],
            },
        }
    }

    tracing::info!(target: "native_ce::standby::verification", "standby suite started");
    let suite_started = std::time::Instant::now();
    let mut check_timings = Vec::new();
    macro_rules! timed {
        ($name:literal, $check:expr) => {{
            on_check($name, None);
            tracing::info!(target: "native_ce::standby::verification",
                check = $name, "standby check started");
            let started = std::time::Instant::now();
            let result = $check;
            let elapsed_ms = started.elapsed().as_millis();
            check_timings.push(ConformanceCheckTiming {
                check: $name.into(),
                elapsed_ms,
            });
            on_check($name, Some(elapsed_ms));
            tracing::info!(target: "native_ce::standby::verification",
                check = $name, elapsed_ms, ok = result.ok, "standby check finished");
            result
        }};
    }
    let mut checks = vec![
        timed!(
            "required-tables",
            guarded("required-tables", check_required_tables(db).await)
        ),
        timed!(
            "event-log-shape",
            guarded("event-log-shape", check_event_log_shape(db).await)
        ),
        timed!(
            "meta-event-log-shape",
            guarded("meta-event-log-shape", check_meta_event_log_shape(db).await)
        ),
        timed!(
            "command-event-log-shapes",
            guarded(
                "command-event-log-shapes",
                check_command_event_log_shapes(db).await,
            )
        ),
        timed!(
            "derivation-request-shape",
            guarded(
                "derivation-request-shape",
                check_derivation_request_shape(db).await,
            )
        ),
        timed!(
            "home-contract",
            guarded("home-contract", check_home_contract(db).await)
        ),
        timed!("rebuild-and-diff", check_rebuild_and_diff(db).await),
        timed!(
            "rebuild-and-diff-meta",
            check_rebuild_and_diff_meta(db).await
        ),
        timed!(
            "rebuild-and-diff-policy",
            check_rebuild_and_diff_policy(db).await
        ),
        timed!(
            "rebuild-and-diff-relationship",
            check_rebuild_and_diff_relationship(db).await
        ),
        timed!(
            "rebuild-and-diff-control",
            check_rebuild_and_diff_control(db).await
        ),
        timed!(
            "rebuild-and-diff-derivation",
            check_rebuild_and_diff_derivation(db).await
        ),
        timed!("provenance-state", check_provenance_state(db).await),
        timed!(
            "authorization-revision-state",
            check_authorization_revision_state(db).await
        ),
        timed!("grant-revision-state", check_grant_revision_state(db).await),
        timed!(
            "authorization-policy-state",
            state(
                "authorization-policy-state",
                crate::authorization::state_violations(db).await,
            )
        ),
        timed!(
            "control-event-log-state",
            state(
                "control-event-log-state",
                crate::control::state_violations(db).await,
            )
        ),
        timed!(
            "policy-event-log-state",
            state(
                "policy-event-log-state",
                crate::policy::state_violations(db).await,
            )
        ),
        timed!(
            "relationship-event-log-state",
            state(
                "relationship-event-log-state",
                crate::relationship::relationship_state_violations(db).await,
            )
        ),
        timed!(
            "portable-identity-state",
            state(
                "portable-identity-state",
                crate::identity::state_violations(db).await,
            )
        ),
        timed!(
            "storage-portability-policy-state",
            match crate::storage_profile::portability_policy_report(db).await {
                Ok(_) => CheckResult {
                    check: "storage-portability-policy-state".into(),
                    ok: true,
                    violations: Vec::new(),
                },
                Err(error) => CheckResult {
                    check: "storage-portability-policy-state".into(),
                    ok: false,
                    violations: vec![format!(
                        "storage portability policy could not be validated: {error}"
                    )],
                },
            }
        ),
    ];
    let ok = checks.iter().all(|check| check.ok);
    tracing::info!(target: "native_ce::standby::verification",
        elapsed_ms = suite_started.elapsed().as_millis(), ok, "standby suite finished");
    ConformanceReport {
        ok,
        checks: std::mem::take(&mut checks),
        profile: None,
        deferred_checks: Vec::new(),
        check_timings,
    }
}

/// Human-readable report, one line per check plus its violations.
pub fn format_report(report: &ConformanceReport) -> String {
    let mut lines = vec![match report.profile {
        Some(profile) => format!("verification profile: {profile}"),
        None => "verification suite: standby admission (observational)".into(),
    }];
    for name in &report.deferred_checks {
        lines.push(format!("DEFERRED  {name}"));
    }
    for c in &report.checks {
        let timing = report
            .check_timings
            .iter()
            .find(|timing| timing.check == c.check)
            .map(|timing| format!("  elapsed_ms={}", timing.elapsed_ms))
            .unwrap_or_default();
        lines.push(format!(
            "{}  {}{}",
            if c.ok { "PASS" } else { "FAIL" },
            c.check,
            timing
        ));
        for v in &c.violations {
            lines.push(format!("      - {v}"));
        }
    }
    lines.push(
        if report.ok {
            "CONFORMANT — spine contract v1 holds"
        } else {
            "NOT CONFORMANT"
        }
        .to_string(),
    );
    lines.join("\n")
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[tokio::test]
    async fn full_conformance_emits_named_start_and_completion_in_report_order() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut progress = Vec::new();
        let report = run_conformance_with_progress(&db, |name, elapsed| {
            progress.push((name.to_owned(), elapsed));
        })
        .await;
        assert!(report.ok, "{}", format_report(&report));
        assert_eq!(report.check_timings.len(), report.checks.len());
        assert_eq!(progress.len(), report.checks.len() * 2);
        for (index, (check, timing)) in report.checks.iter().zip(&report.check_timings).enumerate()
        {
            assert_eq!(timing.check, check.check);
            assert_eq!(progress[index * 2], (check.check.clone(), None));
            assert_eq!(
                progress[index * 2 + 1],
                (check.check.clone(), Some(timing.elapsed_ms))
            );
        }
        db.close().await;
    }
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[tokio::test]
    async fn production_release_dispatch_omits_exactly_eight_checks() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        let mut started = Vec::new();
        let core = run_conformance_with_profile_and_progress(
            &db,
            ConformanceProfile::Core,
            |name, elapsed| {
                if elapsed.is_none() {
                    started.push(name.to_owned());
                }
            },
        )
        .await;
        assert!(core.ok, "{}", format_report(&core));
        assert_eq!(core.profile, Some(ConformanceProfile::Core));
        assert_eq!(core.deferred_checks, PRODUCTION_RELEASE_DEFERRED_CHECKS);
        assert_eq!(
            started,
            core.checks
                .iter()
                .map(|c| c.check.clone())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            started,
            core.check_timings
                .iter()
                .map(|c| c.check.clone())
                .collect::<Vec<_>>()
        );
        for name in PRODUCTION_RELEASE_DEFERRED_CHECKS {
            assert!(
                !started.iter().any(|actual| actual == name),
                "invoked {name}"
            );
        }
        assert!(started
            .iter()
            .any(|name| name == "relationship-append-only-triggers"));
        let full = run_conformance(&db).await;
        assert!(full.ok, "{}", format_report(&full));
        assert_eq!(full.profile, Some(ConformanceProfile::Full));
        assert!(full.deferred_checks.is_empty());
        let mut omitted: Vec<_> = full
            .checks
            .iter()
            .filter(|c| !started.contains(&c.check))
            .map(|c| c.check.as_str())
            .collect();
        omitted.sort_unstable();
        assert_eq!(omitted, PRODUCTION_RELEASE_DEFERRED_CHECKS);
        for check in &full.checks {
            if !PRODUCTION_RELEASE_DEFERRED_CHECKS.contains(&check.check.as_str()) {
                assert!(
                    started.contains(&check.check),
                    "lost retained {}",
                    check.check
                );
            }
        }
        assert_eq!("full".parse(), Ok(ConformanceProfile::Full));
        assert_eq!("production-release".parse(), Ok(ConformanceProfile::Core));
        assert!("core".parse::<ConformanceProfile>().is_err());
        assert_eq!(
            serde_json::to_value(ConformanceProfile::Core).unwrap(),
            "production-release"
        );
        assert_eq!(
            serde_json::to_value(ConformanceProfile::Full).unwrap(),
            "full"
        );
        db.close().await;
    }

    #[tokio::test]
    async fn production_release_refuses_missing_and_changed_relationship_triggers() {
        for (name, event) in [
            ("relationship_events_no_update", "UPDATE"),
            ("relationship_events_no_delete", "DELETE"),
        ] {
            for changed in [false, true] {
                let db = crate::db::create_database(":memory:").await.unwrap();
                let replacement = if changed {
                    format!("CREATE TRIGGER {name} BEFORE {event} ON relationship_events BEGIN SELECT 1; END;")
                } else {
                    String::new()
                };
                // One uncached batch on one connection replaces schema DDL;
                // separate pooled prepared statements are not a fixture boundary.
                sqlx::raw_sql(&format!("DROP TRIGGER {name}; {replacement}"))
                    .execute(db.write_pool())
                    .await
                    .unwrap();
                let report = run_conformance_with_profile(&db, ConformanceProfile::Core).await;
                assert!(!report.ok);
                let check = report
                    .checks
                    .iter()
                    .find(|c| c.check == "relationship-append-only-triggers")
                    .unwrap();
                assert!(!check.ok);
                assert!(
                    check.violations.iter().any(|v| v.contains(name)),
                    "{check:?}"
                );
                db.close().await;
            }
        }
    }

    #[tokio::test]
    async fn production_release_refuses_authorization_trigger_failure() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        sqlx::query("DROP TRIGGER authorization_revision_records_insert")
            .execute(db.write_pool())
            .await
            .unwrap();
        let report = run_conformance_with_profile(&db, ConformanceProfile::Core).await;
        assert!(!report.ok);
        assert!(
            !report
                .checks
                .iter()
                .find(|c| c.check == "authorization-revision-state")
                .unwrap()
                .ok
        );
        db.close().await;
    }

    #[tokio::test]
    async fn full_default_detects_projection_drift_deferred_by_production_release() {
        let db = crate::db::create_database(":memory:").await.unwrap();
        sqlx::query("INSERT INTO links (id,source_id,target_id,relationship,created_at) VALUES ('planted-drift','native:root','native:root','corrupt projection','2026-01-01T00:00:00.000Z')")
            .execute(db.write_pool()).await.unwrap();
        let core = run_conformance_with_profile(&db, ConformanceProfile::Core).await;
        assert!(core.ok, "{}", format_report(&core));
        let full = run_conformance(&db).await;
        assert!(!full.ok);
        assert!(
            !full
                .checks
                .iter()
                .find(|c| c.check == "rebuild-and-diff")
                .unwrap()
                .ok
        );
        let still_present: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM links WHERE id='planted-drift'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(still_present, 1, "verification must not repair drift");
        db.close().await;
    }
}

#[cfg(test)]
mod standby_admission_tests {
    use super::*;
    use tracing::instrument::WithSubscriber;

    fn assert_progress(report: &ConformanceReport, progress: &[(String, Option<u128>)]) {
        assert_eq!(report.check_timings.len(), report.checks.len());
        assert_eq!(progress.len(), report.checks.len() * 2);
        for (index, (check, timing)) in report.checks.iter().zip(&report.check_timings).enumerate()
        {
            assert_eq!(timing.check, check.check);
            assert_eq!(progress[index * 2], (check.check.clone(), None));
            assert_eq!(
                progress[index * 2 + 1],
                (check.check.clone(), Some(timing.elapsed_ms))
            );
        }
    }

    async fn verify_with_progress(readonly: &Db) -> ConformanceReport {
        let mut progress = Vec::new();
        let logs = crate::standby::generation_store::test_diagnostics::Capture::default();
        let report = run_standby_admission_conformance_with_progress(readonly, |name, elapsed| {
            progress.push((name.to_owned(), elapsed));
        })
        .with_subscriber(logs.subscriber())
        .await;
        assert_progress(&report, &progress);
        let output = logs.output();
        assert!(!output.contains("corrupt:link"));
        assert!(output.contains("standby suite started"));
        assert_eq!(
            output
                .lines()
                .filter(|line| line.contains("standby suite finished"))
                .count(),
            1
        );
        assert_eq!(
            output
                .lines()
                .filter(|line| line.contains("standby check finished"))
                .count(),
            report.checks.len()
        );
        assert!(output.contains("standby suite finished elapsed_ms="));
        let suite_end = output
            .lines()
            .find(|line| line.contains("standby suite finished"))
            .unwrap();
        assert!(suite_end.contains(&format!("ok={}", report.ok)));
        for check in &report.checks {
            let end = output
                .lines()
                .find(|line| {
                    line.contains("standby check finished")
                        && line.contains(&format!("check=\"{}\"", check.check))
                })
                .unwrap();
            assert!(end.contains(&format!("ok={}", check.ok)));
        }
        report
    }

    async fn checkpoint_and_verify(path: &std::path::Path) {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(false)
            .read_only(false);
        let mut connection = <sqlx::SqliteConnection as sqlx::Connection>::connect_with(&options)
            .await
            .unwrap();
        let checkpoint: (i64, i64, i64) = sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(checkpoint.0, 0, "WAL checkpoint remained busy");
        let integrity: String = sqlx::query_scalar("PRAGMA quick_check(1)")
            .fetch_one(&mut connection)
            .await
            .unwrap();
        assert_eq!(integrity, "ok");
        <sqlx::SqliteConnection as sqlx::Connection>::close(connection)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn standby_admission_is_read_only_closed_and_detects_semantic_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("candidate.db");
        let db = crate::create_database(path.to_string_lossy().as_ref())
            .await
            .unwrap();
        db.close().await;
        checkpoint_and_verify(&path).await;
        let readonly =
            crate::db::open_existing_database_standby_read_only(path.to_string_lossy().as_ref())
                .await
                .unwrap();
        let report = verify_with_progress(&readonly).await;
        readonly.close().await;
        assert!(report.ok, "{}", format_report(&report));
        assert_eq!(report.profile, None, "standby admission is not FULL");
        let names: std::collections::HashSet<_> = report
            .checks
            .iter()
            .map(|check| check.check.as_str())
            .collect();
        for required in [
            "required-tables",
            "home-contract",
            "rebuild-and-diff",
            "rebuild-and-diff-derivation",
            "provenance-state",
            "authorization-revision-state",
            "portable-identity-state",
        ] {
            assert!(names.contains(required), "missing {required}");
        }
        for excluded in [
            "frozen-ddl",
            "read-log-disposability",
            "closed-types",
            "open-kind",
        ] {
            assert!(!names.contains(excluded), "unexpected {excluded}");
        }

        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(false)
            .read_only(false);
        let mut connection = <sqlx::SqliteConnection as sqlx::Connection>::connect_with(&options)
            .await
            .unwrap();
        let result = sqlx::query(
            "INSERT INTO links \
             (id, source_id, target_id, relationship, note, created_at) \
             VALUES ('corrupt:link', 'native:root', 'native:root', \
                     'corrupt projection', NULL, '2026-01-01T00:00:00.000Z')",
        )
        .execute(&mut connection)
        .await
        .unwrap();
        assert_eq!(result.rows_affected(), 1);
        <sqlx::SqliteConnection as sqlx::Connection>::close(connection)
            .await
            .unwrap();
        checkpoint_and_verify(&path).await;
        let before = std::fs::read(&path).unwrap();
        let readonly =
            crate::db::open_existing_database_standby_read_only(path.to_string_lossy().as_ref())
                .await
                .unwrap();
        let report = verify_with_progress(&readonly).await;
        readonly.close().await;
        assert!(!report.ok);
        assert!(
            !report
                .checks
                .iter()
                .find(|check| check.check == "rebuild-and-diff")
                .unwrap()
                .ok
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
