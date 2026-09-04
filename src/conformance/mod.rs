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

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConformanceReport {
    pub ok: bool,
    pub checks: Vec<CheckResult>,
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
    let mut checks: Vec<CheckResult> = vec![check_frozen_ddl()];
    checks.extend(run_spine_checks(db).await);
    checks.push(check_rebuild_and_diff(db).await);
    checks.push(check_rebuild_and_diff_meta(db).await);
    checks.push(check_rebuild_and_diff_policy(db).await);
    checks.push(check_rebuild_and_diff_relationship(db).await);
    checks.push(check_rebuild_and_diff_control(db).await);
    checks.push(check_rebuild_and_diff_derivation(db).await);
    checks.push(check_provenance_state(db).await);
    checks.push(check_read_log_disposability().await);
    checks.push(check_authorization_revision_state(db).await);
    checks.push(match crate::authorization::state_violations(db).await {
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
    });
    checks.push(match crate::control::state_violations(db).await {
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
    });
    checks.push(match crate::policy::state_violations(db).await {
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
    });
    checks.push(
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
        },
    );
    checks.push(match crate::identity::state_violations(db).await {
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
    });
    ConformanceReport {
        ok: checks.iter().all(|c| c.ok),
        checks,
    }
}

/// Candidate-data admission suite for immutable standby snapshots.
///
/// Unlike [`run_conformance`], every check here is observational with respect
/// to `db`: write probes, the compiled-DDL self-check, and the unrelated
/// read-log fixture are deliberately excluded. Rebuild checks write only their
/// fresh in-memory projections.
pub(crate) async fn run_standby_admission_conformance(db: &Db) -> ConformanceReport {
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

    let mut checks = vec![
        guarded("required-tables", check_required_tables(db).await),
        guarded("event-log-shape", check_event_log_shape(db).await),
        guarded("meta-event-log-shape", check_meta_event_log_shape(db).await),
        guarded(
            "command-event-log-shapes",
            check_command_event_log_shapes(db).await,
        ),
        guarded(
            "derivation-request-shape",
            check_derivation_request_shape(db).await,
        ),
        guarded("home-contract", check_home_contract(db).await),
        check_rebuild_and_diff(db).await,
        check_rebuild_and_diff_meta(db).await,
        check_rebuild_and_diff_policy(db).await,
        check_rebuild_and_diff_relationship(db).await,
        check_rebuild_and_diff_control(db).await,
        check_rebuild_and_diff_derivation(db).await,
        check_provenance_state(db).await,
        check_authorization_revision_state(db).await,
        state(
            "authorization-policy-state",
            crate::authorization::state_violations(db).await,
        ),
        state(
            "control-event-log-state",
            crate::control::state_violations(db).await,
        ),
        state(
            "policy-event-log-state",
            crate::policy::state_violations(db).await,
        ),
        state(
            "relationship-event-log-state",
            crate::relationship::relationship_state_violations(db).await,
        ),
        state(
            "portable-identity-state",
            crate::identity::state_violations(db).await,
        ),
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
        },
    ];
    ConformanceReport {
        ok: checks.iter().all(|check| check.ok),
        checks: std::mem::take(&mut checks),
    }
}

/// Human-readable report, one line per check plus its violations.
pub fn format_report(report: &ConformanceReport) -> String {
    let mut lines: Vec<String> = Vec::new();
    for c in &report.checks {
        lines.push(format!(
            "{}  {}",
            if c.ok { "PASS" } else { "FAIL" },
            c.check
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
mod standby_admission_tests {
    use super::*;

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
        let report = run_standby_admission_conformance(&readonly).await;
        readonly.close().await;
        assert!(report.ok, "{}", format_report(&report));
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
        let report = run_standby_admission_conformance(&readonly).await;
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
